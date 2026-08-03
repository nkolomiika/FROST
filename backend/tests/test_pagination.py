from app.pagination import PageParams, to_paginated_response


def test_page_params_offset_calculation_tc_pag_001() -> None:
    params = PageParams(page=2, size=20)

    assert params.offset == 20


def test_to_paginated_response_for_partial_last_page_tc_pag_001() -> None:
    params = PageParams(page=2, size=20)
    payload = to_paginated_response(items=[1, 2, 3, 4, 5], total=25, params=params)

    assert payload.page == 2
    assert payload.size == 20
    assert payload.total == 25
    assert payload.pages == 2
    assert payload.items == [1, 2, 3, 4, 5]


def test_to_paginated_response_returns_single_page_for_empty_set_tc_pag_002() -> None:
    params = PageParams(page=10, size=20)
    payload = to_paginated_response(items=[], total=0, params=params)

    assert payload.pages == 1
    assert payload.items == []
