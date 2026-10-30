from django.urls import path

from extrato import views

urlpatterns = [
    path("v1/extrato", views.extrato_v1),
    path("v1/extrato.html", views.extrato_html_v1),
    path("v2/extrato", views.extrato_v2),
    path("v2/extrato.html", views.extrato_html_v2),
    path("interno/lancamentos", views.registrar_lancamento),
    path("saude", views.saude),
]
