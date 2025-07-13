# -*- encoding=utf-8 -*-
import configparser
from typing import Optional

try:
    from sqlalchemy import (
        create_engine, MetaData, Table, Column, String, Index,
        inspect, text, exc
    )
    from sqlalchemy.engine.url import make_url
    from sqlalchemy.orm import Session
except ImportError:
    from ..common import MissingPackage

    create_engine = MetaData = Table = Column = String = Index = inspect = text = exc = make_url = Session = MissingPackage("sqlalchemy", "SQL")

from .browser import SQLBrowser
from .mapper import distill_naming, Naming
from ..logging import get_logger
from ..common import coalesce_options
from ..stores import Store
from ..errors import ArgumentError, StoreError, ConfigurationError
from ..browser import Drilldown
from ..cells import Cell
from .utils import CreateTableAsSelect, CreateOrReplaceView
from ..model import string_to_dimension_level


__all__ = ["sqlalchemy_options", "SQLStore"]


# Data types of options passed to sqlalchemy.create_engine
# This is used to coalesce configuration string values into appropriate types
SQLALCHEMY_OPTION_TYPES = {
    "case_sensitive": "bool",
    "case_insensitive": "bool",
    "convert_unicode": "bool",
    "echo": "bool",
    "echo_pool": "bool",
    "implicit_returning": "bool",
    "label_length": "int",
    "max_overflow": "int",
    "pool_size": "int",
    "pool_recycle": "int",
    "pool_timeout": "int",
    "supports_unicode_binds": "bool",
}

# Data types of options passed to the workspace, browser and mapper
# This is used to coalesce configuration string values
OPTION_TYPES = {
    "include_summary": "bool",
    "include_cell_count": "bool",
    "use_denormalization": "bool",
    "safe_labels": "bool",
}


def sqlalchemy_options(options, prefix="sqlalchemy_"):
    """
    Adapta opciones de configuración para `create_engine()` en SQLAlchemy 2.x.
    Elimina el prefijo y transforma los valores usando `coalesce_options`.
    """
    future_safe_keys = [
        "echo", "label_length", "max_overflow", "pool_size",
        "pool_recycle", "pool_timeout", "case_sensitive", "case_insensitive"
    ]

    sa_options = {
        key[len(prefix):]: options.pop(key)
        for key in list(options)
        if key.startswith(prefix)
    }

    # Depurar claves obsoletas o no válidas en SQLAlchemy 2.x
    sa_options = {
        key: value for key, value in sa_options.items()
        if key in future_safe_keys
    }

    # Activar modo moderno
    sa_options["future"] = True

    return coalesce_options(sa_options, SQLALCHEMY_OPTION_TYPES)


class SQLStore(Store):
    def model_provider_name(self):
        return "default"

    default_browser_name = "sql"
    __label__ = ("SQL Store",)
    __description__ = (
        "Relational database store.\n\n"
        "Supported database engines: firebird, mssql, mysql, oracle, postgresql, sqlite, sybase.\n\n"
        "Naming Convention\n"
        "-----------------\n"
        + Naming.__doc__ + "\n"
        "Engine Options\n"
        "--------------\n"
        "Options to be passed to SQLAlchemy create_engine start with prefix `sqlalchemy_`.\n"
        "Example: `sqlalchemy_case_sensitive`. Refer to SQLAlchemy docs for details.\n"
    )
    __options__ = [
        {
            "name": "url",
            "description": "Database URL, such as: postgresql://localhost/dw",
            "type": "string",
        }
    ]

    def __init__(self, url=None, engine=None, metadata=None, **options):
        """
        The options are:

        Required (one of the two, `engine` takes precedence):

        * `url` - database URL in form of:
          ``backend://user:password@host:port/database``
        * `sqlalchemy_options` - this backend accepts options for SQLAlchemy
          in the form: ``option1=value1[&option2=value2]...``
        * `engine` - SQLAlchemy engine - either this or URL should be provided

        Optional:

        * `schema` - default schema, where all tables are located (if not
          explicitly stated otherwise)
        * `fact_prefix` - used by the snowflake mapper to find fact table for a
          cube, when no explicit fact table name is specified
        * `dimension_prefix` - used by snowflake mapper to find dimension
          tables when no explicit mapping is specified
        * `fact_suffix` - used by the snowflake mapper to find fact table for a
          cube, when no explicit fact table name is specified
        * `dimension_suffix` - used by snowflake mapper to find dimension
          tables when no explicit mapping is specified
        * `dimension_schema` – schema where dimension tables are stored, if
          different than common schema.

        Options for denormalized views:

        * `use_denormalization` - browser will use dernormalized view instead
          of snowflake
        * `denormalized_prefix` - if denormalization is used, then this
          prefix is added for cube name to find corresponding cube view
        * `denormalized_schema` - schema wehere denormalized views are
          located (use this if the views are in different schema than fact
          tables, otherwise default schema is going to be used)
        """
        super(SQLStore, self).__init__(**options)

        if not engine and not url:
            raise ConfigurationError(
                "No URL or engine specified in options, provide at least one"
            )
        if engine and url:
            raise ConfigurationError("Both engine and URL specified. Use only one.")

        # Create a copy of options, because we will be popping from it
        self.options = coalesce_options(options, OPTION_TYPES)
        self.naming = distill_naming(self.options)

        if not engine:
            # Process SQLAlchemy options
            sa_options = sqlalchemy_options(options)
            # TODO Maria
            # backend = self._get_backend_from_config()
            # if backend == "postgresql":
            #     sa_options["connect_args"] = {"options": "-c timezone=Europe/Europe"}
            sa_options["future"] = True
            engine = create_engine(url, **sa_options)

        self.logger = get_logger(name=__name__)
        self.connectable = engine
        self.schema = self.naming.schema

        # Load metadata here. This might be too expensive operation to be
        # performed on every request, therefore it is recommended to have one
        # shared open store per process. SQLAlchemy will take care about
        # necessary connections.
        self.metadata = metadata if metadata else MetaData(schema=self.schema)

    def _get_backend_from_config(self, section: str = "store") -> Optional[str]:
        try:
            config = configparser.ConfigParser()
            config.read("slicer.ini")
            if config.has_option(section, "url"):
                url = config.get(section, "url")
                return make_url(url).get_backend_name()
        except Exception:
            pass
        return None

    def _drop_table(self, table, schema, force=False):
        """Drops `table` in `schema`. If table exists, exception is raised
        unless `force` is ``True``"""

        view_name = str(table)
        preparer = self.connectable.dialect.preparer.identifier_preparer
        full_name = preparer.format_table(table)

        if table.exists(self.connectable) and not force:
            raise StoreError(
                "View or table %s (schema: %s) already exists." % (view_name, schema)
            )

        inspector = inspect(self.connectable)
        view_names = inspector.get_view_names(schema=schema)

        with self.connectable.connect() as connection:
            if view_name in view_names:
                # Table is a view
                connection.execute(text(f"DROP VIEW {full_name}"))
            else:
                # Table is a physical table
                table.drop(connection, checkfirst=False)

    def validate(self, cube):
        """Validate physical representation of model. Returns a list of
        dictionaries with keys: ``type``, ``issue``, ``object``.

        Types might be: ``join`` or ``attribute``.

        The ``join`` issues are:

        * ``no_table`` - there is no table for join
        * ``duplicity`` - either table or alias is specified more than once

        The ``attribute`` issues are:

        * ``no_table`` - there is no table for attribute
        * ``no_column`` - there is no column for attribute
        * ``duplicity`` - attribute is found more than once

        """
        issues = []

        tables = set()
        aliases = set()
        alias_map = {}

        for join in cube.joins:
            self.logger.debug("join: %s" % (join,))

            if not join.master.column:
                issues.append(("join", "master column not specified", join))
            if not join.detail.table:
                issues.append(("join", "detail table not specified", join))
            elif join.detail.table == self.mapper.fact_name:
                issues.append(("join", "detail table should not be fact table", join))

            master_table = (join.master.schema, join.master.table)
            tables.add(master_table)

            detail_table = (join.detail.schema, join.detail.table)
            detail_alias = (join.detail.schema, join.alias or join.detail.table)

            if detail_alias in aliases:
                issues.append(
                    ("join", "duplicate detail table %s" % detail_table, join)
                )
            else:
                aliases.add(detail_alias)

            alias_map[detail_alias] = detail_table

            if detail_table in tables and not join.alias:
                issues.append(
                    (
                        "join",
                        "duplicate detail table %s (no alias specified)" % detail_table,
                        join,
                    )
                )
            else:
                tables.add(detail_table)

        # Check for existence of joined tables:
        physical_tables = {}

        # Add fact table to support simple attributes
        physical_tables[(self.fact_table.schema, self.fact_table.name)] = (
            self.fact_table
        )
        for schema_name, table_name in tables:
            schema = schema_name or self.mapper.schema
        try:
            physical_table = Table(
                table_name,
                self.metadata,
                schema=schema,
                autoload_with=self.connectable
            )
            physical_tables[(schema, table_name)] = physical_table
        except exc.NoSuchTableError:
            issues.append(("join", f"table {schema}.{table_name} does not exist", join))

        base = cube.all_fact_attributes
        mappings = {attr.name: self.mapper.physical(attr) for attr in base}

        for attr, ref in mappings.items():
            alias_ref = (ref.schema, ref.table)
            table_ref = alias_map.get(alias_ref, alias_ref)
            table = physical_tables.get(table_ref)

            if table is None:
                issues.append(
                    (
                        "attribute",
                        "table %s.%s does not exist for attribute %s"
                        % (table_ref[0], table_ref[1], self.mapper.logical(attr)),
                        attr,
                    )
                )
            else:
                if ref.column not in table.c:
                    issues.append(
                        (
                            "attribute",
                            "column %s.%s.%s does not exist for attribute %s"
                            % (
                                table_ref[0],
                                table_ref[1],
                                ref.column,
                                self.mapper.logical(attr),
                            ),
                            attr,
                        )
                    )

        return issues

    def create_denormalized_view(
        self,
        cube,
        view_name=None,
        materialize=False,
        replace=False,
        create_index=False,
        keys_only=False,
        schema=None,
    ):
        """Creates a denormalized view named `view_name` of a `cube`. If
        `view_name` is ``None`` then view name is constructed by pre-pending
        value of `denormalized_view_prefix` from workspace options to the cube
        name. If no prefix is specified in the options, then view name will be
        equal to the cube name.

        Options:

        * `materialize` - whether the view is materialized (a table) or
          regular view
        * `replace` - if `True` then existing table/view will be replaced,
          otherwise an exception is raised when trying to create view/table
          with already existing name
        * `create_index` - if `True` then index is created for each key
          attribute. Can be used only on materialized view, otherwise raises
          an exception
        * `keys_only` - if ``True`` then only key attributes are used in the
          view, all other detail attributes are ignored
        * `schema` - target schema of the denormalized view, if not specified,
          then `denormalized_view_schema` from options is used if specified,
          otherwise default workspace schema is used (same schema as fact
          table schema).
        """

        browser = SQLBrowser(cube, self, schema=schema)

        if browser.safe_labels:
            raise ConfigurationError(
                "Denormalization does not work with " "safe_labels turned on"
            )

        # Note: this does not work with safe labels – since they are "safe"
        # they can not conform to the cubes implicit naming schema dim.attr

        (statement, _) = browser.denormalized_statement(
            attributes, include_fact_key=True
        )

        schema = schema or self.naming.schema
        view_name = view_name or self.naming.denormalized_table_name(cube.name)

        fact_name = cube.fact or self.naming.fact_table_name(cube.name)

        if fact_name == view_name and schema == self.naming.schema:
            raise StoreError(
                "target denormalized view is the same as source fact table"
            )

        table = Table(view_name, self.metadata, schema=schema)
        view_names = inspector.get_view_names(schema=schema)
        table_names = inspector.get_table_names(schema=schema)

        if view_name in view_names or view_name in table_names:
            self._drop_table(table, schema, force=replace)

        create_view = (
            CreateTableAsSelect(table, statement) if materialize
            else CreateOrReplaceView(table, statement)
        )

        self.logger.info(
            "creating denormalized view %s (materialized: %s)"
            % (str(table), materialize)
        )
        # print("SQL statement:\n%s" % statement)
        self.execute(create_view)
        if create_index:
            if not materialize:
                raise ConfigurationError("Indexes can only be created on materialized views")
            table = Table(view_name, self.metadata, schema=schema, autoload_with=self.connectable)

            insp = reflection.Inspector.from_engine(engine)
            insp.reflecttable(table, None)

            for attribute in attributes:
                label = attribute.ref
                self.logger.info("creating index for %s" % label)
                column = table.c[label]
                name = "idx_%s_%s" % (view_name, label)
                index = Index(name, column)
                with self.connectable.connect() as conn:
                    index.create(conn)


    def execute(self, statement):
        with Session(self.connectable) as session:
            return session.execute(statement)


    def validate_model(self):
        issues = []
        for cube in self.model.cubes:
            browser = self.browser(cube)
            issues += browser.validate()
        return issues


    ########################################################################
    ########################################################################
    ##
    ## Aggregates
    ##
    """
    Aggregate specification:
        * cube
        * dimensions, "grain" (levels) + required dimensions
        * aggregate schema
        * aggregate table
        * create_dimensions? flag

    Grain dimension:
        * Name: prefix_dimension_level
        * Attributes: all level attributes
        * NON-UNIQUE level key: join will have to be composed of multiple keys
        * UNIQUE level key: join might be based on level key
    """

    def create_conformed_rollup(
        self, cube, dimension, level=None, hierarchy=None, replace=False, **options
    ):
        """Extracts dimension values at certain level into a separate table.
        The new table name will be composed of `dimension_prefix`, dimension
        name and suffixed by dimension level. For example a product dimension
        at category level with prefix `dim_` will be called
        ``dim_product_category``

        Attributes:

        * `dimension` – dimension to be extracted
        * `level` – grain level
        * `hierarchy` – hierarchy to be used
        * `schema` – target schema
        * `dimension_prefix` – prefix used for the dimension table
        * `dimension_suffix` – suffix used for the dimension table
        * `replace` – if ``True`` then existing table will be replaced,
          otherwise an exception is raised if table already exists.
        """

        raise NotImplementedError("Requires to be updated to new query builder")

        naming = distill_naming(options)
        context = QueryContext(cube, mapper, schema=schema, metadata=self.metadata)

        dimension = cube.dimension(dimension)
        hierarchy = dimension.hierarchy(hierarchy)
        if level:
            depth = hierarchy.level_index(dimension.level(level)) + 1
        else:
            depth = len(hierarchy)

        if depth == 0:
            raise ArgumentError("Depth for dimension values should not be 0")
        elif depth is not None:
            levels = hierarchy.levels[0:depth]

        attributes = []
        for level in levels:
            attributes.extend(level.attributes)

        statement = context.denormalized_statement(
            attributes=attributes, include_fact_key=False
        )

        group_by = [context.column(attr) for attr in attributes]
        statement = statement.group_by(*group_by)

        table_name = "%s%s%s_%s" % (
            dimension_prefix or "",
            dimension_suffix or "",
            str(dimension),
            str(level),
        )
        self.create_table_from_statement(
            table_name, statement, schema, replace, insert=True
        )

    def create_conformed_rollups(
        self,
        cube,
        dimensions,
        grain=None,
        schema=None,
        dimension_prefix=None,
        dimension_suffix=None,
        replace=False,
    ):
        """Extract multiple dimensions from a snowflake. See
        `extract_dimension()` for more information. `grain` is a dictionary
        where keys are dimension names and values are levels, if level is
        ``None`` then all levels are considered."""

        grain = grain or {}

        for dim in dimensions:
            dim = cube.dimension(dim)
            level = grain.get(str(dim))
            hierarchy = dim.hierarchy()
            if level:
                level_index = hierarchy.level_index(level)
            else:
                level_index = len(hierarchy)

            for depth in range(0, level_index):
                level = hierarchy[depth]
                self.create_conformed_rollup(
                    cube,
                    dim,
                    level=level,
                    schema=schema,
                    dimension_prefix=dimension_prefix or "",
                    dimension_suffix=dimension_suffix or "",
                    replace=replace,
                )


    def create_table_from_statement(
        self, table_name, statement, schema, replace=False, insert=False
    ):
        """Creates or replaces a table from statement.

        Arguments:

        * `table_name` - name of target table
        * `schema` – target table schema
        * `statement` – SQL statement used to get structure of the new table
        * `insert` – if `True` then data are inserted from the statement,
          otherwise only empty table is created. Defaut is `False`
        * `replace` – if `True` old table will be dropped, otherwise if table
          already exists an exception is raised.
        """

        #
        # Create table
        #
        table = Table(table_name, self.metadata, schema=schema)

        inspector = inspect(self.connectable)
        if table_name in inspector.get_table_names(schema=schema):
            self._drop_table(table, schema, force=replace)

        for col in statement.columns:
            # mysql backend requires default string length
            if (
                self.connectable.name == "mysql"
                and isinstance(col.type, String)
                and not col.type.length
            ):
                col_type = String(255)
            else:
                col_type = col.type

            new_col = Column(col.name, col_type)
            table.append_column(new_col)

        self.logger.info("creating table '%s'" % str(table))
        self.metadata.create_all(self.connectable, tables=[table])

        if insert:
            self.logger.debug("inserting into table '%s'" % str(table))
            insert_statement = table.insert().from_select(statement.columns, statement)
            self.execute(insert_statement)

        return table

    def create_cube_aggregate(
        self,
        cube,
        table_name=None,
        dimensions=None,
        replace=False,
        create_index=False,
        schema=None,
    ):
        """Creates an aggregate table. If dimensions is `None` then all cube's
        dimensions are considered.

        Arguments:

        * `dimensions`: list of dimensions to use in the aggregated cuboid, if
          `None` then all cube dimensions are used
        """

        browser = SQLBrowser(cube, self, schema=schema)

        if browser.safe_labels:
            raise ConfigurationError(
                "Aggregation does not work with " "safe_labels turned on"
            )

        schema = schema or self.naming.aggregate_schema or self.naming.schema

        table_name = table_name or self.naming.aggregate_table_name(cube.name)
        fact_name = cube.fact or self.naming.fact_table_name(cube.name)

        dimensions = dimensions or [dim.name for dim in cube.dimensions]

        if fact_name == table_name and schema == self.naming.schema:
            raise StoreError("Aggregation target is the same as fact")

        drilldown = []
        keys = []
        for dimref in dimensions:
            (dimname, hiername, level) = string_to_dimension_level(dimref)
            dimension = cube.dimension(dimname)
            hierarchy = dimension.hierarchy(hiername)
            levels = hierarchy.levels
            drilldown.append((dimension, hierarchy, levels[-1]))
            keys += [l.key for l in levels]

        cell = Cell(cube)
        drilldown = Drilldown(drilldown, cell)

        # Create statement of all dimension level keys for
        # getting structure for table creation
        (statement, _) = browser.aggregation_statement(
            cell, drilldown=drilldown, aggregates=cube.aggregates
        )

        # Create table
        table = self.create_table_from_statement(
            table_name, statement, schema=schema, replace=replace, insert=False
        )

        self.logger.info("Inserting...")

        insert = table.insert().from_select(statement.columns, statement)
        self.execute(insert)

        self.logger.info("Done")

        if create_index:
            self.logger.info("Creating indexes...")
            aggregated_columns = [a.name for a in cube.aggregates]
            for column in table.columns:
                if column.name in aggregated_columns:
                    continue

                name = "%s_%s_idx" % (table_name, column)
                self.logger.info("creating index: %s" % name)
                index = Index(name, column)
                index.create(self.connectable)

        self.logger.info("Done")


class SQLSchemaInspector(object):
    """
    Object that discovers fact and dimension tables in a database according
    to specified configuration and naming conventions.
    """

    def __init__(self, engine, naming, metadata=None):
        """Creates an inspector that discovers tables in a database according
        to specified configuration and naming conventions."""
        self.engine = engine
        self.naming = naming
        self.metadata = metadata or MetaData()

        self.inspector = inspect(engine)

    def discover_fact_tables(self):
        """discovers tables that might be fact tables by name."""

        schema = self.naming.fact_schema or self.naming.schema
        names = self.inspector.get_table_names(schema)

        return self.naming.facts(names)

    def discover_dimension_tables(self):
        """discovers tables that might be dimension tables by name."""

        schema = self.naming.dimension_schema or self.naming.schema
        names = self.inspector.get_table_names(schema)

        return self.naming.dimensions(names)
