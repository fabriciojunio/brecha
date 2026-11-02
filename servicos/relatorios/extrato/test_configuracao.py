import os
import tempfile
from unittest import mock

from django.test import SimpleTestCase

from relatorios.settings import obrigatorio, segredo


class SegredoTest(SimpleTestCase):
    def test_le_do_arquivo_quando_existe(self):
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as arquivo:
            arquivo.write("valor-do-arquivo\n")
        self.addCleanup(os.remove, arquivo.name)
        with mock.patch.dict(os.environ, {"TESTE_ARQUIVO": arquivo.name, "TESTE": "valor-da-variavel"}):
            self.assertEqual(segredo("TESTE"), "valor-do-arquivo")

    def test_sem_arquivo_usa_a_variavel(self):
        with mock.patch.dict(os.environ, {"TESTE": "valor-da-variavel"}, clear=False):
            os.environ.pop("TESTE_ARQUIVO", None)
            self.assertEqual(segredo("TESTE"), "valor-da-variavel")

    def test_obrigatorio_vazio_impede_a_subida(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NAO_EXISTE", None)
            os.environ.pop("NAO_EXISTE_ARQUIVO", None)
            with self.assertRaisesRegex(RuntimeError, "NAO_EXISTE"):
                obrigatorio("NAO_EXISTE")
