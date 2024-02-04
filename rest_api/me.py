from quart import Blueprint, current_app as app, request, abort
import pymongo

import security
from database import db, get_total_pages


me_bp = Blueprint("me_bp", __name__, url_prefix="/me")


@me_bp.get("/reports")
async def get_report_history():
    # Check authorization
    if not request.user:
        abort(401)

    # Get page
    try:
        page = int(request.args["page"])
    except:
        page = 1

    # Get reports
    reports = list(
        db.reports.find(
            {"reports.user": request.user},
            projection={"escalated": 0},
            sort=[("reports.time", pymongo.DESCENDING)],
            skip=(page - 1) * 25,
            limit=25,
        )
    )

    # Get reason, comment, and time
    for report in reports:
        for _report in report["reports"]:
            if _report["user"] == request.user:
                report.update({
                    "reason": _report["reason"],
                    "comment": _report["comment"],
                    "time": _report["time"]
                })
        del report["reports"]

    # Get content
    for report in reports:
        if report["type"] == "post":
            report["content"] = db.posts.find_one(
                {"_id": report.get("content_id")}, projection={"_id": 1, "u": 1, "isDeleted": 1}
            )
        elif report["type"] == "user":
            report["content"] = security.get_account(report.get("content_id"))

    # Return reports
    payload = {
        "error": False,
        "page#": page,
        "pages": get_total_pages("reports", {"reports.user": request.user}),
    }
    if "autoget" in request.args:
        payload["autoget"] = reports
    else:
        payload["index"] = [report["_id"] for report in reports]
    return payload, 200
