import gc

import pytest


@pytest.fixture(autouse=True)
def _release_project_between_tests():
    """Only one Project may exist at a time (project.Project enforces this).

    Each test constructs its own Project; BinaryFunction <-> FunctionBlock form
    a reference cycle, so the project is only reclaimed by cyclic GC, not plain
    refcounting. Force a collection after every test so the previous project's
    __del__ runs and frees the singleton slot before the next test builds one.
    """
    yield
    gc.collect()
