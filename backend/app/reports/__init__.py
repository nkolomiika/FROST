"""Генерация отчётов по проектам."""

from app.reports.word_builder import ReportKind, build_pp, build_szi, load_template

__all__ = ["ReportKind", "build_szi", "build_pp", "load_template"]
