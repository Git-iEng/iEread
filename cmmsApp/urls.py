from django.urls import path
from . import views

app_name = "cmmsApp"

urlpatterns = [
    # ============================================================
    # iEread Website - Main Pages
    # ============================================================
    path("", views.home, name="home"),
    path("contact/", views.contact, name="contact"),

    # ============================================================
    # iEread - Request Demo
    # ============================================================
    path(
        "request-demo/",
        views.request_demo_view,
        name="request_demo",
    ),

    # ============================================================
    # iEread - Email OTP Verification
    # ============================================================
    path(
        "api/contact/send-email-otp/",
        views.send_email_otp,
        name="send_email_otp",
    ),

    path(
        "api/contact/verify-email-otp/",
        views.verify_email_otp,
        name="verify_email_otp",
    ),

    # ============================================================
    # iEread - Contact Form and Helpers
    # ============================================================
    path(
        "contact/submit/",
        views.contact_block_submit,
        name="contact_submit",
    ),

    path(
        "contact/phone-info/",
        views.phone_info,
        name="phone_info",
    ),

    path(
        "contact/country-list/",
        views.country_list,
        name="country_list",
    ),

    # ============================================================
    # iEread - Thank You Page
    # ============================================================
    path(
        "thanks/",
        views.contact_thanks,
        name="contact_thanks",
    ),

    # ============================================================
    # iEread - Sitemap
    # ============================================================
    path(
        "sitemap.xml",
        views.sitemap,
        name="sitemap",
    ),
]