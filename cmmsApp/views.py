from html import escape
from threading import Thread
import hashlib
import hmac
import re
import secrets
import time

import phonenumbers
import pycountry
import requests

from django.conf import settings
from django.contrib import messages
from django.contrib.staticfiles.storage import staticfiles_storage
from django.core import signing
from django.core.exceptions import ValidationError
from django.core.mail import EmailMultiAlternatives, get_connection
from django.core.validators import validate_email
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST


# ============================================================
# iEread Website Configuration
# ============================================================

PRODUCT_NAME = "iEread"


# ============================================================
# Validation
# ============================================================

NAME_RE = re.compile(r"^[A-Za-z\s'.-]{2,}$")
PHONE_RE = re.compile(r"^\+?\d[\d\s\-()]{6,}$")


# ============================================================
# Email Helpers
# ============================================================

def _send_email(
    subject: str,
    text_body: str,
    html_body: str | None,
    recipients: list[str] | None,
):
    """
    Common email sender used by Request Demo and Contact forms.
    """

    try:
        if not recipients:

            fallback = (
                getattr(settings, "EMAIL_HOST_USER", None)
                or getattr(settings, "DEFAULT_FROM_EMAIL", None)
            )

            recipients = [fallback] if fallback else []

        if not recipients:
            print("EMAIL WARNING: No recipients configured.")
            return

        connection = get_connection(
            timeout=getattr(settings, "EMAIL_TIMEOUT", 15)
        )

        email_message = EmailMultiAlternatives(
            subject=subject,
            body=text_body,
            from_email=(
                getattr(settings, "DEFAULT_FROM_EMAIL", None)
                or getattr(settings, "EMAIL_HOST_USER", None)
            ),
            to=recipients,
            connection=connection,
        )

        if html_body:
            email_message.attach_alternative(
                html_body,
                "text/html"
            )

        email_message.send(
            fail_silently=False
        )

    except Exception as exc:
        print(
            "EMAIL ERROR:",
            repr(exc)
        )


def _send_demo_email_async(
    subject: str,
    text_body: str,
    html_body: str | None = None,
):
    """
    Send Request Demo email asynchronously.
    """

    recipients = (
        getattr(settings, "DEMO_RECIPIENTS", None)
        or getattr(settings, "CONTACT_RECIPIENTS", None)
    )

    Thread(
        target=_send_email,
        args=(
            subject,
            text_body,
            html_body,
            recipients,
        ),
        daemon=True,
    ).start()


def _send_contact_email_async(
    subject: str,
    text_body: str,
    html_body: str | None = None,
):
    """
    Send Contact form email asynchronously.
    """

    recipients = getattr(
        settings,
        "CONTACT_RECIPIENTS",
        None
    )

    Thread(
        target=_send_email,
        args=(
            subject,
            text_body,
            html_body,
            recipients,
        ),
        daemon=True,
    ).start()


# ============================================================
# EMAIL OTP VERIFICATION
# ============================================================

CONTACT_OTP_EXPIRY_SECONDS = 3 * 60

CONTACT_OTP_RESEND_SECONDS = 60

CONTACT_OTP_MAX_ATTEMPTS = 5

CONTACT_VERIFICATION_TOKEN_MAX_AGE = 15 * 60

CONTACT_OTP_SESSION_KEY = "contact_email_otp"

CONTACT_VERIFIED_SESSION_KEY = "contact_email_verified"

CONTACT_VERIFICATION_SALT = (
    "contact-email-verification-v1"
)


def _normalise_email(
    email: str
) -> str:

    return (
        email or ""
    ).strip().lower()


def _hash_contact_otp(
    email: str,
    otp: str
) -> str:

    message = (
        f"{_normalise_email(email)}:{otp}"
    ).encode("utf-8")

    key = settings.SECRET_KEY.encode(
        "utf-8"
    )

    return hmac.new(
        key,
        message,
        hashlib.sha256
    ).hexdigest()


# ============================================================
# SEND OTP EMAIL
# ============================================================

def _send_contact_otp_email(
    email: str,
    otp: str
):
    """
    Send iEread email verification OTP.
    """

    subject = (
        "iEread Email Verification Code"
    )

    expiry_minutes = (
        CONTACT_OTP_EXPIRY_SECONDS // 60
    )

    text_body = (

        "Verify your email address\n\n"

        "Please use the following OTP to verify "
        "your email address for your iEread "
        "website enquiry.\n\n"

        f"{otp}\n\n"

        f"This OTP will expire in "
        f"{expiry_minutes} minutes.\n"

        "If you did not request this verification, "
        "please ignore this email."
    )

    safe_otp = escape(
        str(otp)
    )

    html_body = f"""
    <!DOCTYPE html>

    <html lang="en">

    <head>

        <meta charset="UTF-8">

        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >

    </head>

    <body
        style="
            margin:0;
            padding:0;
            background-color:#f4f7fb;
            font-family:Arial,Helvetica,sans-serif;
            color:#172033;
        "
    >

        <table
            role="presentation"
            width="100%"
            cellpadding="0"
            cellspacing="0"
            border="0"
            style="
                width:100%;
                background-color:#f4f7fb;
            "
        >

            <tr>

                <td
                    align="center"
                    style="padding:32px 20px;"
                >

                    <table
                        role="presentation"
                        width="520"
                        cellpadding="0"
                        cellspacing="0"
                        border="0"
                        style="
                            width:100%;
                            max-width:520px;
                            background:#ffffff;
                            border-radius:14px;
                        "
                    >

                        <tr>

                            <td
                                style="
                                    padding:30px;
                                "
                            >

                                <div
                                    style="
                                        font-size:14px;
                                        font-weight:700;
                                        color:#28B6F6;
                                        margin-bottom:8px;
                                    "
                                >
                                    iEread
                                </div>


                                <div
                                    style="
                                        font-size:23px;
                                        line-height:30px;
                                        font-weight:bold;
                                        color:#062846;
                                        margin-bottom:14px;
                                    "
                                >
                                    Verify your email address
                                </div>


                                <div
                                    style="
                                        font-size:15px;
                                        line-height:23px;
                                        color:#475569;
                                        margin-bottom:24px;
                                    "
                                >

                                    Please use the following OTP
                                    to verify your email address
                                    for your iEread website enquiry.

                                </div>


                                <div
                                    style="
                                        display:inline-block;
                                        padding:16px 22px;
                                        border-radius:10px;
                                        background:#f0efff;
                                        font-size:30px;
                                        line-height:36px;
                                        font-weight:bold;
                                        letter-spacing:7px;
                                        color:#5145E5;
                                        white-space:nowrap;
                                        margin-bottom:24px;
                                    "
                                >

                                    {safe_otp}

                                </div>


                                <div
                                    style="
                                        font-size:15px;
                                        line-height:22px;
                                        margin-bottom:12px;
                                    "
                                >

                                    This OTP will expire in

                                    <strong>
                                        {expiry_minutes} minutes.
                                    </strong>

                                </div>


                                <div
                                    style="
                                        font-size:13px;
                                        line-height:20px;
                                        color:#64748b;
                                    "
                                >

                                    If you did not request this
                                    verification, please ignore
                                    this email.

                                </div>

                            </td>

                        </tr>

                    </table>

                </td>

            </tr>

        </table>

    </body>

    </html>
    """

    connection = get_connection(
        timeout=getattr(
            settings,
            "EMAIL_TIMEOUT",
            15
        )
    )

    email_message = EmailMultiAlternatives(

        subject=subject,

        body=text_body,

        from_email=(

            getattr(
                settings,
                "DEFAULT_FROM_EMAIL",
                None
            )

            or getattr(
                settings,
                "EMAIL_HOST_USER",
                None
            )

        ),

        to=[email],

        connection=connection,

    )

    email_message.attach_alternative(
        html_body,
        "text/html"
    )

    email_message.send(
        fail_silently=False
    )


# ============================================================
# SEND EMAIL OTP API
# ============================================================

@require_POST
def send_email_otp(request):

    email = _normalise_email(
        request.POST.get(
            "email",
            ""
        )
    )

    try:

        validate_email(
            email
        )

    except ValidationError:

        return JsonResponse(

            {
                "ok": False,
                "message":
                    "Please enter a valid email address."
            },

            status=400,

        )


    now = int(
        time.time()
    )


    current = (

        request.session.get(
            CONTACT_OTP_SESSION_KEY
        )

        or {}

    )


    if current.get("email") == email:

        elapsed = (
            now
            - int(
                current.get(
                    "sent_at"
                )
                or 0
            )
        )


        if elapsed < CONTACT_OTP_RESEND_SECONDS:

            remaining = (
                CONTACT_OTP_RESEND_SECONDS
                - elapsed
            )

            return JsonResponse(

                {

                    "ok": False,

                    "message":
                        f"Please wait {remaining} seconds "
                        "before requesting another OTP.",

                    "resend_in":
                        remaining,

                },

                status=429,

            )


    otp = (
        f"{secrets.randbelow(1_000_000):06d}"
    )


    request.session[
        CONTACT_OTP_SESSION_KEY
    ] = {

        "email":
            email,

        "otp_hash":
            _hash_contact_otp(
                email,
                otp
            ),

        "sent_at":
            now,

        "expires_at":
            now
            + CONTACT_OTP_EXPIRY_SECONDS,

        "attempts":
            0,

    }


    request.session.pop(

        CONTACT_VERIFIED_SESSION_KEY,

        None

    )


    request.session.modified = True


    try:

        _send_contact_otp_email(
            email,
            otp
        )


    except Exception as exc:

        print(
            "OTP EMAIL ERROR:",
            repr(exc)
        )


        request.session.pop(

            CONTACT_OTP_SESSION_KEY,

            None

        )


        request.session.modified = True


        return JsonResponse(

            {

                "ok":
                    False,

                "message":
                    "We could not send the "
                    "verification code. "
                    "Please try again.",

            },

            status=500,

        )


    return JsonResponse(

        {

            "ok":
                True,

            "message":
                "Verification code sent.",

            "expires_in":
                CONTACT_OTP_EXPIRY_SECONDS,

            "resend_in":
                CONTACT_OTP_RESEND_SECONDS,

        }

    )


# ============================================================
# VERIFY EMAIL OTP
# ============================================================

@require_POST
def verify_email_otp(request):

    email = _normalise_email(

        request.POST.get(
            "email",
            ""
        )

    )


    otp = (

        request.POST.get(
            "otp"
        )

        or ""

    ).strip()


    if not re.fullmatch(
        r"\d{6}",
        otp
    ):

        return JsonResponse(

            {

                "ok":
                    False,

                "message":
                    "Please enter the 6-digit "
                    "verification code.",

            },

            status=400,

        )


    state = (

        request.session.get(
            CONTACT_OTP_SESSION_KEY
        )

        or {}

    )


    if (
        not state
        or state.get("email") != email
    ):

        return JsonResponse(

            {

                "ok":
                    False,

                "message":
                    "Please request a new "
                    "verification code.",

            },

            status=400,

        )


    now = int(
        time.time()
    )


    if now > int(
        state.get(
            "expires_at"
        )

        or 0
    ):

        request.session.pop(
            CONTACT_OTP_SESSION_KEY,
            None
        )

        request.session.modified = True


        return JsonResponse(

            {

                "ok":
                    False,

                "message":
                    "The verification code "
                    "has expired. Please resend it.",

            },

            status=400,

        )


    attempts = int(
        state.get(
            "attempts"
        )

        or 0
    )


    if attempts >= CONTACT_OTP_MAX_ATTEMPTS:

        request.session.pop(
            CONTACT_OTP_SESSION_KEY,
            None
        )

        request.session.modified = True


        return JsonResponse(

            {

                "ok":
                    False,

                "message":
                    "Too many incorrect attempts. "
                    "Please request a new code.",

            },

            status=429,

        )


    expected_hash = (
        state.get(
            "otp_hash"
        )

        or ""
    )


    supplied_hash = (
        _hash_contact_otp(
            email,
            otp
        )
    )


    if not hmac.compare_digest(
        expected_hash,
        supplied_hash
    ):

        state["attempts"] = (
            attempts + 1
        )

        request.session[
            CONTACT_OTP_SESSION_KEY
        ] = state

        request.session.modified = True


        return JsonResponse(

            {

                "ok":
                    False,

                "message":
                    "Incorrect verification code.",

            },

            status=400,

        )


    nonce = (
        secrets.token_urlsafe(
            24
        )
    )


    request.session[
        CONTACT_VERIFIED_SESSION_KEY
    ] = {

        "email":
            email,

        "nonce":
            nonce,

        "verified_at":
            now,

    }


    request.session.pop(
        CONTACT_OTP_SESSION_KEY,
        None
    )


    request.session.modified = True


    verification_token = signing.dumps(

        {

            "email":
                email,

            "nonce":
                nonce,

        },

        salt=CONTACT_VERIFICATION_SALT,

        compress=True,

    )


    return JsonResponse(

        {

            "ok":
                True,

            "verified":
                True,

            "message":
                "Email verified successfully.",

            "verification_token":
                verification_token,

        }

    )


# ============================================================
# CHECK EMAIL VERIFICATION
# ============================================================

def _is_contact_email_verified(
    request,
    email: str,
    token: str
) -> bool:

    email = _normalise_email(
        email
    )

    token = (
        token or ""
    ).strip()


    if (
        not email
        or not token
    ):

        return False


    try:

        payload = signing.loads(

            token,

            salt=CONTACT_VERIFICATION_SALT,

            max_age=(
                CONTACT_VERIFICATION_TOKEN_MAX_AGE
            ),

        )


    except signing.BadSignature:

        return False


    verified = (

        request.session.get(
            CONTACT_VERIFIED_SESSION_KEY
        )

        or {}

    )


    return (

        _normalise_email(
            payload.get(
                "email",
                ""
            )
        )
        == email

        and

        _normalise_email(
            verified.get(
                "email",
                ""
            )
        )
        == email

        and

        bool(
            payload.get(
                "nonce"
            )
        )

        and

        hmac.compare_digest(

            str(
                payload.get(
                    "nonce",
                    ""
                )
            ),

            str(
                verified.get(
                    "nonce",
                    ""
                )
            ),

        )

    )


def _consume_contact_email_verification(
    request
):

    request.session.pop(
        CONTACT_VERIFIED_SESSION_KEY,
        None
    )

    request.session.modified = True


# ============================================================
# HOME PAGE
# ============================================================

def home(request):

    return render(

        request,

        "index.html",

        {
            "RECAPTCHA_SITE_KEY":
                settings.RECAPTCHA_SITE_KEY
        }

    )


# ============================================================
# CONTACT URL
# ============================================================

def contact(request):
    """
    The iEread website Contact section is on index.html.
    /contact/ therefore returns users to that section.
    """

    return redirect(
        "/#contact"
    )


# ============================================================
# REQUEST DEMO
# ============================================================

def request_demo_view(request):

    if request.method != "POST":

        return redirect(
            "/"
        )


    wants_json = (

        request.headers.get(
            "x-requested-with"
        )

        == "XMLHttpRequest"

    )


    if not verify_recaptcha(
        request
    ):

        if wants_json:

            return JsonResponse(

                {

                    "ok":
                        False,

                    "errors":
                        {
                            "captcha":
                                "Please complete the CAPTCHA."
                        },

                },

                status=400,

            )


        messages.error(

            request,

            "Please complete the CAPTCHA."

        )


        return redirect(

            request.META.get(
                "HTTP_REFERER",
                "/"
            )

        )


    full_name = (

        request.POST.get(
            "full_name"
        )

        or ""

    ).strip()


    company = (

        request.POST.get(
            "company"
        )

        or ""

    ).strip()


    email = _normalise_email(

        request.POST.get(
            "email",
            ""
        )

    )


    verification_token = (

        request.POST.get(
            "email_verification_token"
        )

        or ""

    ).strip()


    phone = (

        request.POST.get(
            "phone"
        )

        or ""

    ).strip()


    country = (

        request.POST.get(
            "country"
        )

        or ""

    ).strip()


    address = (

        request.POST.get(
            "address"
        )

        or ""

    ).strip()


    enquiry_message = (

        request.POST.get(
            "message"
        )

        or ""

    ).strip()


    errors = {}


    if not NAME_RE.match(
        full_name
    ):

        errors[
            "full_name"
        ] = (
            "Please enter a valid "
            "full name (letters only)."
        )


    if not company:

        errors[
            "company"
        ] = (
            "Company is required."
        )


    try:

        validate_email(
            email
        )


    except ValidationError:

        errors[
            "email"
        ] = (
            "Enter a valid email address."
        )


    if not PHONE_RE.match(
        phone
    ):

        errors[
            "phone"
        ] = (
            "Enter a valid phone number."
        )


    if not country:

        errors[
            "country"
        ] = (
            "Select a country."
        )


    if errors:

        if wants_json:

            return JsonResponse(

                {

                    "ok":
                        False,

                    "errors":
                        errors,

                },

                status=400,

            )


        for error_message in (
            errors.values()
        ):

            messages.error(

                request,

                error_message

            )


        return redirect(

            request.META.get(
                "HTTP_REFERER",
                "/"
            )

        )


    if not _is_contact_email_verified(

        request,

        email,

        verification_token

    ):

        if wants_json:

            return JsonResponse(

                {

                    "ok":
                        False,

                    "errors":
                        {

                            "email":
                                "Please verify your "
                                "email address."

                        },

                },

                status=400,

            )


        messages.error(

            request,

            "Please verify your email address."

        )


        return redirect(

            request.META.get(
                "HTTP_REFERER",
                "/"
            )

        )


    country_code, dial = (

        country.split(
            "|",
            1
        )

        + [""]

    )[:2]


    subject = (
        "New iEread Enquiry"
    )


    text_body = "\n".join(

        [

            "A new iEread enquiry was submitted:",

            f"Full name: {full_name}",

            f"Company: {company}",

            f"Email: {email}",

            f"Phone: {phone}",

            (
                f"Country: "
                f"{country_code} {dial}"
            ).strip(),

            f"Address: {address}",

            "",

            "Message:",

            enquiry_message
            or "(none)",

        ]

    )


    html_body = f"""

        <h2
            style="
                margin:0 0 8px;
                color:#062846;
            "
        >
            New iEread Enquiry
        </h2>


        <table
            cellpadding="6"
            cellspacing="0"
            style="
                border-collapse:collapse;
                background:#f4f7fb;
            "
        >

            <tr>
                <td>
                    <b>Full name</b>
                </td>

                <td>
                    {escape(full_name)}
                </td>
            </tr>


            <tr>
                <td>
                    <b>Company</b>
                </td>

                <td>
                    {escape(company)}
                </td>
            </tr>


            <tr>
                <td>
                    <b>Email</b>
                </td>

                <td>
                    {escape(email)}
                </td>
            </tr>


            <tr>
                <td>
                    <b>Phone</b>
                </td>

                <td>
                    {escape(phone)}
                </td>
            </tr>


            <tr>
                <td>
                    <b>Country</b>
                </td>

                <td>
                    {escape(country_code)} {escape(dial)}
                </td>
            </tr>


            <tr>
                <td>
                    <b>Address</b>
                </td>

                <td>
                    {escape(address)}
                </td>
            </tr>

        </table>


        <p
            style="
                margin:12px 0 4px;
            "
        >
            <b>Message</b>
        </p>


        <pre
            style="
                white-space:pre-wrap;
                font-family:
                    system-ui,
                    Segoe UI,
                    Arial,
                    sans-serif;
            "
        >{escape(enquiry_message or "(none)")}</pre>

    """


    _send_demo_email_async(

        subject,

        text_body,

        html_body

    )


    _consume_contact_email_verification(
        request
    )


    thanks_url = reverse(
        "cmmsApp:contact_thanks"
    )


    if wants_json:

        return JsonResponse(

            {

                "ok":
                    True,

                "redirect":
                    thanks_url,

            }

        )


    return redirect(
        thanks_url
    )


# ============================================================
# OPTIONAL REQUEST DEMO TEMPLATE VIEW
# ============================================================

def request_demo(request):

    return render(

        request,

        "request_demo_modal.html",

        {

            "RECAPTCHA_SITE_KEY":
                settings.RECAPTCHA_SITE_KEY

        },

    )


# ============================================================
# SITEMAP
# ============================================================

def sitemap(request):

    with staticfiles_storage.open(
        "sitemap.xml"
    ) as sitemap_file:

        sitemap_content = (
            sitemap_file.read()
        )


    return HttpResponse(

        sitemap_content,

        content_type="application/xml"

    )


# ============================================================
# COUNTRY PHONE HELPER
# ============================================================

def _dial_code_from_alpha2(
    alpha2: str
) -> str:

    if not alpha2:

        return ""


    try:

        country_code = (

            phonenumbers
            .country_code_for_region(

                alpha2.upper()

            )

        )


        return (

            f"+{country_code}"

            if country_code

            else ""

        )


    except Exception:

        return ""


# ============================================================
# PHONE INFORMATION
# ============================================================

def phone_info(request):

    phone = (

        request.GET.get(
            "phone"
        )

        or ""

    ).strip()


    country_value = (

        request.GET.get(
            "country"
        )

        or ""

    ).strip()


    resolved_alpha2 = ""

    resolved_country_name = ""

    e164 = ""


    # --------------------------------------------------------
    # Find country
    # --------------------------------------------------------

    if country_value:

        upper_country = (
            country_value.upper()
        )


        if (
            len(upper_country) == 2
            and upper_country.isalpha()
        ):

            resolved_alpha2 = (
                upper_country
            )


        else:

            for item in (
                pycountry.countries
            ):

                if (
                    item.name.lower()
                    == country_value.lower()
                ):

                    resolved_alpha2 = (
                        item.alpha_2
                    )

                    break


    # --------------------------------------------------------
    # Parse phone
    # --------------------------------------------------------

    if phone:

        try:

            parsed_phone = (
                phonenumbers.parse(

                    phone,

                    resolved_alpha2
                    or None

                )
            )


            if phonenumbers.is_possible_number(
                parsed_phone
            ):

                e164 = (
                    phonenumbers.format_number(

                        parsed_phone,

                        phonenumbers
                        .PhoneNumberFormat
                        .E164

                    )
                )


                region = (
                    phonenumbers
                    .region_code_for_number(
                        parsed_phone
                    )
                )


                if region:

                    resolved_alpha2 = (
                        region
                    )


        except Exception:

            pass


    # --------------------------------------------------------
    # Country name
    # --------------------------------------------------------

    if resolved_alpha2:

        try:

            country_object = (
                pycountry.countries.get(
                    alpha_2=resolved_alpha2
                )
            )


            if country_object:

                resolved_country_name = (
                    country_object.name
                )


        except Exception:

            pass


    dial = _dial_code_from_alpha2(
        resolved_alpha2
    )


    example = ""


    if (
        dial
        and phone
        and not phone.startswith("+")
    ):

        example = (
            f"{dial} 4xxxxxxxx"
        )


    elif (
        dial
        and not phone
    ):

        example = (
            f"{dial} 4xxxxxxxx"
        )


    return JsonResponse(

        {

            "e164":
                e164,

            "country":
                resolved_country_name,

            "alpha2":
                resolved_alpha2,

            "dial_code":
                dial,

            "example":
                example,

        }

    )


# ============================================================
# COUNTRY LIST
# ============================================================

def country_list(request):

    data = []


    for country_item in (
        pycountry.countries
    ):

        try:

            country_code = (

                phonenumbers
                .country_code_for_region(

                    country_item.alpha_2

                )

            )


        except Exception:

            country_code = None


        if country_code:

            data.append(

                {

                    "alpha2":
                        country_item.alpha_2,

                    "name":
                        country_item.name,

                    "dial":
                        f"+{country_code}",

                }

            )


    data.sort(

        key=lambda item:
            item["name"]

    )


    return JsonResponse(

        data,

        safe=False

    )


# ============================================================
# CONTACT BLOCK SUBMIT
# ============================================================

def contact_block_submit(request):

    if request.method != "POST":

        return redirect(

            request.META.get(
                "HTTP_REFERER",
                "/"
            )

        )


    if not verify_recaptcha(
        request
    ):

        messages.error(

            request,

            "Please complete the CAPTCHA."

        )


        return redirect(

            request.META.get(
                "HTTP_REFERER",
                "/"
            )

        )


    name = (

        request.POST.get(
            "name"
        )

        or ""

    ).strip()


    email = _normalise_email(

        request.POST.get(
            "email",
            ""
        )

    )


    verification_token = (

        request.POST.get(
            "email_verification_token"
        )

        or ""

    ).strip()


    phone = (

        request.POST.get(
            "phone"
        )

        or ""

    ).strip()


    country_value = (

        request.POST.get(
            "country"
        )

        or ""

    ).strip()


    enquiry_message = (

        request.POST.get(
            "message"
        )

        or ""

    ).strip()


    errors = []


    if not NAME_RE.match(
        name
    ):

        errors.append(
            "Please enter a valid name."
        )


    try:

        validate_email(
            email
        )


    except ValidationError:

        errors.append(
            "Enter a valid email address."
        )


    if not PHONE_RE.match(
        phone
    ):

        errors.append(
            "Enter a valid phone number."
        )


    if (
        not country_value
        and not phone.startswith("+")
    ):

        errors.append(
            "Please enter your country."
        )


    if errors:

        for error_message in errors:

            messages.error(
                request,
                error_message
            )


        return redirect(

            request.META.get(
                "HTTP_REFERER",
                "/"
            )

        )


    if not _is_contact_email_verified(

        request,

        email,

        verification_token

    ):

        messages.error(

            request,

            "Please verify your email address."

        )


        return redirect(

            request.META.get(
                "HTTP_REFERER",
                "/"
            )

        )


    subject = (

        f"[iEread Website] "
        f"Demo request: {name}"

    )


    text_body = "\n".join(

        [

            (
                "A new demo request was "
                "submitted for iEread:"
            ),

            f"Name: {name}",

            f"Email: {email}",

            f"Phone: {phone}",

            f"Country: {country_value}",

            "",

            "Message:",

            enquiry_message
            or "(none)",

        ]

    )


    _send_contact_email_async(

        subject,

        text_body,

        None

    )


    _consume_contact_email_verification(
        request
    )


    return redirect(

        reverse(
            "cmmsApp:contact_thanks"
        )

    )


# ============================================================
# THANK YOU PAGE
# ============================================================

def contact_thanks(request):

    return render(

        request,

        "contact_thanks.html",

        {}

    )


# ============================================================
# GOOGLE RECAPTCHA
# ============================================================

def verify_recaptcha(request):

    captcha_response = (

        request.POST.get(
            "g-recaptcha-response"
        )

        or ""

    ).strip()


    if not captcha_response:

        print(
            "reCAPTCHA failed: "
            "no captcha response"
        )

        return False


    data = {

        "secret":
            settings.RECAPTCHA_SECRET_KEY,

        "response":
            captcha_response,

    }


    try:

        response = requests.post(

            "https://www.google.com/"
            "recaptcha/api/siteverify",

            data=data,

            timeout=10

        )


        result = (
            response.json()
        )


        print(
            "reCAPTCHA result:",
            result
        )


        return result.get(
            "success",
            False
        )


    except requests.RequestException as exc:

        print(

            "reCAPTCHA request error:",

            str(exc)

        )


        return False