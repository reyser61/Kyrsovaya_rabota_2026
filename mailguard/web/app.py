"""Flask-приложение: дашборд, список инцидентов, детали, экспорт отчётов."""

from __future__ import annotations

import os

from flask import (
    Flask,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from ..blocklist import Blocklist
from ..config import load_config
from ..engine import AnalysisResult, Engine
from ..reporting import to_csv, to_html, to_json
from ..rules import Rule, RuleRegistry
from ..storage import Storage

# соответствие типов собранных IoC -> типов блок-листа
_IOC_TO_BL = {"ip": "ip", "sender_email": "email", "sender_domain": "domain",
              "url_domain": "domain", "file_sha256": "file_sha256", "subject": "subject"}

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAMPLE_POSTFIX = os.path.join(PROJECT_ROOT, "data", "sample_logs", "postfix.log")
SAMPLE_DOVECOT = os.path.join(PROJECT_ROOT, "data", "sample_logs", "dovecot.log")
SAMPLE_EMAILS = os.path.join(PROJECT_ROOT, "data", "sample_emails")

CATEGORY_RU = {
    "phishing": "Фишинг",
    "dlp": "Утечка данных",
    "account": "Компрометация аккаунта",
}
SEVERITY_RU = {
    "low": "низкая",
    "medium": "средняя",
    "high": "высокая",
    "critical": "критическая",
}
CONFIDENCE_RU = {"low": "низкая", "medium": "средняя", "high": "высокая"}
IOC_TYPE_RU = {
    "ip": "IP-адрес",
    "sender_email": "e-mail отправителя",
    "sender_domain": "домен отправителя",
    "url_domain": "домен из ссылки",
    "file_sha256": "хэш вложения",
    "subject": "тема письма",
}


def create_app(config_path: str | None = None, db_path: str | None = None) -> Flask:
    app = Flask(__name__)
    app.secret_key = "mailguard-coursework-secret"
    app.config["CONFIG_PATH"] = config_path
    app.config["DB_PATH"] = db_path

    def get_storage() -> Storage:
        return Storage(app.config["DB_PATH"])

    def get_registry() -> RuleRegistry:
        return RuleRegistry(load_config(app.config["CONFIG_PATH"]))

    def get_blocklist() -> Blocklist:
        cfg = load_config(app.config["CONFIG_PATH"])
        path = cfg.raw.get("ioc", {}).get("blocklist_file")
        if path and not os.path.isabs(path):
            path = os.path.join(PROJECT_ROOT, path)
        return Blocklist(path)

    def get_engine() -> Engine:
        return Engine(load_config(app.config["CONFIG_PATH"]))

    # --- Jinja-фильтры локализации ---
    app.jinja_env.filters["cat_ru"] = lambda c: CATEGORY_RU.get(c, c)
    app.jinja_env.filters["sev_ru"] = lambda s: SEVERITY_RU.get(s, s)
    app.jinja_env.filters["conf_ru"] = lambda c: CONFIDENCE_RU.get(c, c)
    app.jinja_env.filters["ioc_ru"] = lambda t: IOC_TYPE_RU.get(t, t)

    # ------------------------------------------------------------------ #

    @app.route("/")
    def dashboard():
        storage = get_storage()
        stats = storage.latest_stats()
        top_incidents = storage.get_incidents()[:10]
        storage.close()
        return render_template(
            "dashboard.html",
            stats=stats,
            top_incidents=top_incidents,
            has_data=bool(stats),
        )

    @app.route("/incidents")
    def incidents():
        category = request.args.get("category") or None
        severity = request.args.get("severity") or None
        storage = get_storage()
        items = storage.get_incidents(category=category, severity=severity)
        storage.close()
        return render_template(
            "incidents.html",
            incidents=items,
            category=category,
            severity=severity,
        )

    @app.route("/incident/<int:incident_id>")
    def incident_detail(incident_id: int):
        storage = get_storage()
        item = storage.get_incident(incident_id)
        storage.close()
        if not item:
            abort(404)
        # сопоставляем сработавшие правила с их метаданными (для ссылок)
        reg = get_registry()
        triggered = []
        for rid in item.get("evidence", {}).get("triggered_rules", []):
            r = reg.get(rid)
            triggered.append({"id": rid, "name": r.name if r else rid,
                              "exists": r is not None})
        from ..narrative import recommendation
        return render_template("incident_detail.html", inc=item,
                               triggered=triggered,
                               recommendation=recommendation(item["category"]))

    @app.route("/rule/<rule_id>")
    def rule_detail(rule_id: str):
        reg = get_registry()
        rule = reg.get(rule_id)
        if not rule:
            abort(404)
        return render_template("rule_detail.html", r=rule)

    @app.route("/ioc")
    def ioc():
        type_ = request.args.get("type") or None
        storage = get_storage()
        items = storage.get_iocs(type_=type_)
        storage.close()
        return render_template("ioc.html", iocs=items, type=type_)

    @app.route("/analyze", methods=["POST"])
    def analyze():
        postfix = request.form.get("postfix_log") or SAMPLE_POSTFIX
        dovecot = request.form.get("dovecot_log") or SAMPLE_DOVECOT
        emails = request.form.get("emails_dir") or SAMPLE_EMAILS
        if not os.path.exists(postfix) and not os.path.exists(dovecot) \
                and not os.path.isdir(emails):
            flash("Файлы логов/писем не найдены. Сгенерируйте тестовые данные.", "error")
            return redirect(url_for("dashboard"))
        storage = get_storage()
        engine = get_engine()
        engine.run(
            postfix_log=postfix if os.path.exists(postfix) else None,
            dovecot_log=dovecot if os.path.exists(dovecot) else None,
            emails_dir=emails if os.path.isdir(emails) else None,
            storage=storage,
        )
        storage.close()
        flash("Анализ завершён.", "ok")
        return redirect(url_for("dashboard"))

    @app.route("/upload", methods=["GET", "POST"])
    def upload():
        """Загрузка собственных логов/писем. Файлы НАКАПЛИВАЮТСЯ и анализируются
        вместе с основным набором — результаты добавляются, а не заменяют."""
        if request.method == "GET":
            return render_template("upload.html")

        from glob import glob
        import time as _time
        from werkzeug.utils import secure_filename

        updir = os.path.join(PROJECT_ROOT, "data", "uploads")
        pf_dir = os.path.join(updir, "postfix")
        dc_dir = os.path.join(updir, "dovecot")
        eml_dir = os.path.join(updir, "emails")
        for d in (pf_dir, dc_dir, eml_dir):
            os.makedirs(d, exist_ok=True)
        stamp = str(int(_time.time() * 1000))   # уникальный префикс имени

        n_pf = n_dc = n_eml = 0
        pf = request.files.get("postfix_log")
        if pf and pf.filename:
            pf.save(os.path.join(pf_dir, f"{stamp}_{secure_filename(pf.filename)}"))
            n_pf = 1
        dc = request.files.get("dovecot_log")
        if dc and dc.filename:
            dc.save(os.path.join(dc_dir, f"{stamp}_{secure_filename(dc.filename)}"))
            n_dc = 1
        for f in request.files.getlist("emails"):
            if f and f.filename and f.filename.lower().endswith(".eml"):
                f.save(os.path.join(eml_dir, f"{stamp}_{secure_filename(f.filename)}"))
                n_eml += 1

        if not (n_pf or n_dc or n_eml):
            flash("Не выбрано ни одного файла (.log или .eml).", "error")
            return redirect(url_for("upload"))

        # Анализируем образцы + ВСЕ накопленные загрузки вместе.
        postfix_logs = ([SAMPLE_POSTFIX] if os.path.exists(SAMPLE_POSTFIX) else []) \
            + sorted(glob(os.path.join(pf_dir, "*")))
        dovecot_logs = ([SAMPLE_DOVECOT] if os.path.exists(SAMPLE_DOVECOT) else []) \
            + sorted(glob(os.path.join(dc_dir, "*")))
        emails_dirs = ([SAMPLE_EMAILS] if os.path.isdir(SAMPLE_EMAILS) else []) + [eml_dir]

        storage = get_storage()
        get_engine().run(postfix_log=postfix_logs, dovecot_log=dovecot_logs,
                         emails_dir=emails_dirs, storage=storage)
        storage.close()
        flash(f"Загружено и добавлено к анализу: postfix {n_pf}, dovecot {n_dc}, "
              f"писем {n_eml}. Результаты объединены с основным набором.", "ok")
        return redirect(url_for("dashboard"))

    @app.route("/upload/reset", methods=["POST"])
    def upload_reset():
        """Удаляет накопленные загрузки и пересчитывает только основной набор."""
        updir = os.path.join(PROJECT_ROOT, "data", "uploads")
        if os.path.isdir(updir):
            for root, _, files in os.walk(updir):
                for f in files:
                    try:
                        os.remove(os.path.join(root, f))
                    except OSError:
                        pass
        storage = get_storage()
        get_engine().run(
            postfix_log=SAMPLE_POSTFIX if os.path.exists(SAMPLE_POSTFIX) else None,
            dovecot_log=SAMPLE_DOVECOT if os.path.exists(SAMPLE_DOVECOT) else None,
            emails_dir=SAMPLE_EMAILS if os.path.isdir(SAMPLE_EMAILS) else None,
            storage=storage,
        )
        storage.close()
        flash("Загруженные файлы очищены, дашборд сброшен к основному набору.", "ok")
        return redirect(url_for("upload"))

    @app.route("/report.<fmt>")
    def report(fmt: str):
        """Экспорт отчёта. Пересобираем результат из сэмпл-логов на лету."""
        engine = get_engine()
        result: AnalysisResult = engine.run(
            postfix_log=SAMPLE_POSTFIX if os.path.exists(SAMPLE_POSTFIX) else None,
            dovecot_log=SAMPLE_DOVECOT if os.path.exists(SAMPLE_DOVECOT) else None,
            emails_dir=SAMPLE_EMAILS if os.path.isdir(SAMPLE_EMAILS) else None,
        )
        if fmt == "json":
            return Response(to_json(result), mimetype="application/json")
        if fmt == "csv":
            return Response(
                to_csv(result),
                mimetype="text/csv",
                headers={"Content-Disposition": "attachment; filename=mailguard_report.csv"},
            )
        if fmt == "html":
            return Response(to_html(result), mimetype="text/html")
        abort(404)

    # ---------------------- Панель правил ------------------------------- #

    @app.route("/rules")
    def rules():
        reg = get_registry()
        all_rules = reg.all()
        groups = {
            "phishing": [r for r in all_rules if r.category == "phishing"],
            "dlp": [r for r in all_rules if r.category == "dlp"],
            "account": [r for r in all_rules if r.category == "account"],
        }
        return render_template(
            "rules.html",
            groups=groups,
            total=len(all_rules),
            enabled=sum(1 for r in all_rules if r.enabled),
            declarative=sum(1 for r in all_rules if r.source == "declarative"),
        )

    @app.route("/rules/toggle", methods=["POST"])
    def rules_toggle():
        rule_id = request.form.get("rule_id", "")
        enabled = request.form.get("enabled") == "1"
        reg = get_registry()
        if reg.set_enabled(rule_id, enabled):
            flash(f"Правило {rule_id}: {'включено' if enabled else 'выключено'}.", "ok")
        else:
            flash(f"Правило {rule_id} не найдено.", "error")
        return redirect(url_for("rules"))

    @app.route("/rules/create", methods=["POST"])
    def rules_create():
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Укажите название правила.", "error")
            return redirect(url_for("rules"))
        patterns = [p.strip() for p in re_split(request.form.get("patterns", ""))
                    if p.strip()]
        if not patterns:
            flash("Укажите хотя бы один шаблон.", "error")
            return redirect(url_for("rules"))

        rule_id = (request.form.get("rule_id") or "").strip()
        if not rule_id:
            slug = "".join(ch if ch.isalnum() else "_" for ch in name.lower())[:30]
            rule_id = f"custom.{slug or 'rule'}"

        reg = get_registry()
        if reg.get(rule_id):
            flash(f"Правило с id {rule_id} уже существует.", "error")
            return redirect(url_for("rules"))

        try:
            weight = int(request.form.get("weight", "20"))
        except ValueError:
            weight = 20

        reg.add_declarative(Rule(
            id=rule_id,
            name=name,
            description=(request.form.get("description") or "").strip(),
            category=request.form.get("category", "phishing"),
            default_weight=weight,
            weight=weight,
            enabled=True,
            source="declarative",
            rtype=request.form.get("rtype", "keyword"),
            field_scope=request.form.get("field_scope", "both"),
            patterns=patterns,
        ))
        flash(f"Правило «{name}» создано ({rule_id}).", "ok")
        return redirect(url_for("rules"))

    # ---------------------- Блок-лист IoC (этап D) ---------------------- #

    @app.route("/blocklist")
    def blocklist():
        bl = get_blocklist()
        return render_template("blocklist.html", entries=bl.all(), total=bl.count())

    @app.route("/blocklist/add", methods=["POST"])
    def blocklist_add():
        bl = get_blocklist()
        ok = bl.add(request.form.get("type", ""), request.form.get("value", ""),
                    request.form.get("source") or "manual")
        if ok:
            bl.save()
            flash("Индикатор добавлен в блок-лист.", "ok")
        else:
            flash("Не удалось добавить (неверный тип или дубликат).", "error")
        return redirect(url_for("blocklist"))

    @app.route("/blocklist/import", methods=["POST"])
    def blocklist_import():
        bl = get_blocklist()
        entries: list[tuple[str, str, str]] = []
        for line in (request.form.get("data") or "").splitlines():
            parts = [p.strip() for p in line.replace(";", ",").split(",")]
            if len(parts) >= 2 and parts[0] and parts[1]:
                entries.append((parts[0], parts[1],
                                parts[2] if len(parts) > 2 else "import"))
        added = bl.add_many(entries)
        flash(f"Импортировано индикаторов: {added}.", "ok")
        return redirect(url_for("blocklist"))

    @app.route("/blocklist/promote", methods=["POST"])
    def blocklist_promote():
        """Добавляет в блок-лист собранные системой IoC (high/critical)."""
        storage = get_storage()
        iocs = storage.get_iocs()
        storage.close()
        bl = get_blocklist()
        entries = [(_IOC_TO_BL[i["type"]], i["value"], "promoted")
                   for i in iocs if i["type"] in _IOC_TO_BL]
        added = bl.add_many(entries)
        flash(f"Добавлено из собранных IoC: {added}.", "ok")
        return redirect(url_for("blocklist"))

    return app


def re_split(text: str) -> list[str]:
    """Разбивает ввод шаблонов по переводам строк, запятым и точкам с запятой."""
    import re
    return re.split(r"[\n,;]+", text or "")
