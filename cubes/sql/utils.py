# -*- encoding: utf-8 -*-
"""Cubes SQL backend utilities, mostly to be used by the slicer command."""

from sqlalchemy import text
from sqlalchemy.sql.expression import Executable, ClauseElement
from sqlalchemy.ext.compiler import compiles
import sqlalchemy.sql as sql

from collections import OrderedDict

from ..browser import SPLIT_DIMENSION_NAME
from ..cells import Cell
from ..model import collect_attributes

__all__ = [
    "CreateTableAsSelect",
    "InsertIntoAsSelect",
    "CreateOrReplaceView",
    "condition_conjunction",
    "order_column",
    "order_query",
    "paginate_query"
]

class CreateTableAsSelect(Executable, ClauseElement):
    def __init__(self, table, select):
        self.table = table
        self.select = select

@compiles(CreateTableAsSelect)
def visit_create_table_as_select(element, compiler, **kw):
    preparer = compiler.dialect.preparer(compiler.dialect)
    full_name = preparer.format_table(element.table)

    return "CREATE TABLE %s AS (%s)" % (
        element.table,
        compiler.process(element.select)
    )
@compiles(CreateTableAsSelect, "sqlite")
def visit_create_table_as_select(element, compiler, **kw):
    preparer = compiler.dialect.preparer(compiler.dialect)
    full_name = preparer.format_table(element.table)

    return "CREATE TABLE %s AS %s" % (
        element.table,
        compiler.process(element.select)
    )

class CreateOrReplaceView(Executable, ClauseElement):
    def __init__(self, view, select):
        self.view = view
        self.select = select

@compiles(CreateOrReplaceView)
def visit_create_or_replace_view(element, compiler, **kw):
    preparer = compiler.dialect.preparer(compiler.dialect)
    full_name = preparer.format_table(element.view)

    return "CREATE OR REPLACE VIEW %s AS (%s)" % (
        full_name,
        compiler.process(element.select)
    )

@compiles(CreateOrReplaceView, "sqlite")
def visit_create_or_replace_view(element, compiler, **kw):
    preparer = compiler.dialect.preparer(compiler.dialect)
    full_name = preparer.format_table(element.view)

    return "CREATE VIEW %s AS %s" % (
        full_name,
        compiler.process(element.select)
    )

@compiles(CreateOrReplaceView, "mysql")
def visit_create_or_replace_view(element, compiler, **kw):
    preparer = compiler.dialect.preparer(compiler.dialect)
    full_name = preparer.format_table(element.view)

    return "CREATE OR REPLACE VIEW %s AS %s" % (
        full_name,
        compiler.process(element.select)
    )


def paginate_query(statement, page, page_size):
    """Returns paginated statement if page is provided, otherwise returns
    the same statement."""

    if page is not None and page_size is not None:
        statement = statement.offset(page * page_size).limit(page_size)

    return statement


def order_column(column, order):
    """Orders a `column` according to `order` specified as string. Returns a
    `Column` expression"""

    if not order:
        return column
    elif order.lower().startswith("asc"):
        return column.asc()
    elif order.lower().startswith("desc"):
        return column.desc()
    else:
        raise ArgumentError("Unknown order %s for column %s") % (order, column)


def order_query(statement, order, natural_order=None, labels=None):
    """Returns a SQL statement which is ordered according to the `order`. If
    the statement contains attributes that have natural order specified, then
    the natural order is used, if not overriden in the `order`.

    * `statement` – statement to be ordered
    * `order` explicit order, list of tuples (`aggregate`, `direction`)
    * `natural_order` – natural order of attributes in the statement – a
       dictionary where keys are attribute names and vales are directions.
       Used to look-up the natural order.
    * `labels` – mapping between logical labels and physical labels. Important
      when `safe_labels` is enabled. Read more about `safe_labels` for more
      information.
    """

    order = order or []
    labels = labels or {}
    natural_order = natural_order or []

    final_order = OrderedDict()

    # Each attribute mentioned in the order should be present in the selection
    # or as some column from joined table. Here we get the list of already
    # selected columns and derived aggregates

    # Get logical attributes from column labels (see logical_labels
    # description for more information why this step is necessary)

    columns = OrderedDict(zip(labels, statement.columns))

    # Normalize order
    # ---------------
    # Make sure that the `order` is a list of of tuples (`attribute`,
    # `order`). If element of the `order` list is a string, then it is
    # converted to (`string`, ``None``).

    if SPLIT_DIMENSION_NAME in statement.columns:
        split_column = sql.expression.column(SPLIT_DIMENSION_NAME)
        final_order[SPLIT_DIMENSION_NAME] = split_column

    # Collect the corresponding attribute columns
    for attribute, direction in order:
        attribute = str(attribute)
        column = order_column(columns[attribute], direction)

        if attribute not in final_order:
            final_order[attribute] = column

    # Collect natural order for selected columns that have no explicit
    # ordering
    for (name, column) in columns.items():
        if name in natural_order and name not in order_by:
            final_order[name] = order_column(column, natural_order[name])

    statement = statement.order_by(*final_order.values())

    return statement


def extract_permissions_from_cell(cell):
    aux_cell = Cell(cube=cell.cube, cuts=cell.cuts) if cell else None

    permissions_cell = None
    permissions_cuts = (
        [cut for cut in aux_cell.cuts if cut.dimension.info.get('type', None) == 'Permission'] if aux_cell else []
    )
    if permissions_cuts:
        permissions_cell = Cell(cube=aux_cell.cube, cuts=permissions_cuts)
        aux_cell.cuts = [
            cut for cut in aux_cell.cuts if cut not in permissions_cell.cuts
        ]

    return (aux_cell, permissions_cell)


def apply_permissions_to_statement(sql_browser, statement, permissions_cell):
    if (
        sql_browser is not None
        and statement is not None
        and permissions_cell is not None
    ):
        permission_refs = collect_attributes([], permissions_cell)
        permission_attributes = permissions_cell.cube.get_attributes(
            permission_refs, aggregated=True
        )
        permission_context = sql_browser._create_context(permission_attributes)
        permission_selection = [sql_browser.star.fact_key_column]
        permission_condition = permission_context.condition_for_cell(
            permissions_cell
        )
        permission_subquery = sql.expression.subquery(
            "allowed_records",
            columns=permission_selection,
            from_obj=permission_context.star,
            whereclause=permission_condition,
            use_labels=True,
            distinct=True
        )
        fact_pk = "{}.{}".format(
            permissions_cell.cube.fact, permissions_cell.cube.key
        )
        statement.append_whereclause(
            text(fact_pk) == permission_subquery.c.__fact_key__
        )
