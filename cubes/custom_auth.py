# -*- encoding: utf-8 -*-

from __future__ import absolute_import
from collections import defaultdict
import json
import codecs

from .cells import Cell, cut_from_string, cut_from_dict
from .model import string_to_dimension_level
from .errors import ConfigurationError
from .auth import Authorizer, ALL_CUBES_WILDCARD
from . import compat


class _DematAccessRight(object):
    def __init__(self, allowed_cubes=[], denied_cubes=[], cell_restrictions={},
                 hierarchy_limits=[]):

        self.cell_restrictions = cell_restrictions or {}

        self.hierarchy_limits = defaultdict(list)

        if hierarchy_limits:
            for cube, limits in hierarchy_limits.items():
                for limit in limits:
                    if isinstance(limit, compat.string_type):
                        limit = string_to_dimension_level(limit)
                    self.hierarchy_limits[cube].append(limit)

        self.hierarchy_limits = dict(self.hierarchy_limits)

        self.allowed_cubes = set(allowed_cubes) if allowed_cubes else set([])
        self.denied_cubes = set(denied_cubes) if denied_cubes else set([])

        self._get_patterns()

    def _get_patterns(self):
        self.allowed_cube_suffix = []
        self.allowed_cube_prefix = []
        self.denied_cube_suffix = []
        self.denied_cube_prefix = []

        for cube in self.allowed_cubes:
            if cube.startswith("*"):
                self.allowed_cube_suffix.append(cube[1:])
            if cube.endswith("*"):
                self.allowed_cube_prefix.append(cube[:-1])

        for cube in self.denied_cubes:
            if cube.startswith("*"):
                self.denied_cube_suffix.append(cube[1:])
            if cube.endswith("*"):
                self.denied_cube_prefix.append(cube[:-1])

    def is_allowed(self, name, allow_after_denied=True):
        allow = False
        if self.allowed_cubes:
            if (name in self.allowed_cubes) or (ALL_CUBES_WILDCARD in self.allowed_cubes):
                allow = True

            if not allow and self.allowed_cube_prefix:
                allow = any(name.startswith(p) for p in self.allowed_cube_prefix)
            if not allow and self.allowed_cube_suffix:
                allow = any(name.endswith(p) for p in self.allowed_cube_suffix)

        deny = False
        if self.denied_cubes:
            if (name in self.denied_cubes) or (ALL_CUBES_WILDCARD in self.denied_cubes):
                deny = True

            if not deny and self.denied_cube_prefix:
                deny = any(name.startswith(p) for p in self.denied_cube_prefix)
            if not deny and self.denied_cube_suffix:
                deny = any(name.endswith(p) for p in self.denied_cube_suffix)

        """
        Four cases:
            - allow match, no deny match
              * allow_deny: allowed
              * deny_allow: allowed
            - no allow match, deny match
              * allow_deny: denied
              * deny_allow: denied
            - no match in either
              * allow_deny: denied
              * deny_allow: allowed
            - match in both
              * allow_deny: denied
              * deny_allow: allowed
        """

        # deny_allow
        if allow_after_denied:
            return allow or not deny
        # allow_deny
        else:
            return allow and not deny


class DematAuthorizer(Authorizer):
    __options__ = [
        {
            "name": "url",
            "description": "DeMaT OLAP Cubes API base url",
            "type": "string"
        },
        {
            "name": "authorize_method",
            "description": "Authorize method name",
            "type": "string"
        },
        {
            "name": "restricted_cell_method",
            "description": "Restricted Cell method name",
            "type": "string"
        },
        {
            "name": "hierarchy_limits_method",
            "description": "Hierarchy Limits method name",
            "type": "string"
        },
        {
            "name": "order",
            "description": "Order of allow/deny",
            "type": "string",
            "values": ["allow_deny", "deny_allow"]
        },
    ]

    def __init__(self, url=None, authorize_method='authorize', restricted_cell_method='restricted-cell', hierarchy_limits_method='hierarchy-limits', order=None, **options):
        """Creates a Demat based authorizer. Reads data from Demat"""

        super(DematAuthorizer, self).__init__()

        if url:
            self.url = url
        else:
            raise ConfigurationError("Missing authorizer url")

        self.authorize_method = authorize_method
        self.restricted_cell_method = restricted_cell_method
        self.hierarchy_limits_method = hierarchy_limits_method

        order = order or "deny_allow"
        if order == "allow_deny":
            self.allow_after_denied = False
        elif order == "deny_allow":
            self.allow_after_denied = True
        else:
            raise ConfigurationError("Unknown allow/deny order: %s" % order)

    def _rightRequest(self, identity, method, cube=None):
        opener = compat.build_opener()
        opener.addheaders = [('Authorization', 'Token {token}'.format(token=identity))]

        url = '{url}{method}/'.format(url=self.url, method=method)
        if cube:
            url = '{url}?cube={cube}'.format(url=url, cube=cube)

        response = opener.open(url)
        reader = codecs.getreader("utf-8")
        return json.load(reader(response))

    def authorize(self, identity, cubes):
        try:
            data = self._rightRequest(identity, self.authorize_method)
            right = _DematAccessRight(
                allowed_cubes=data.get('allowed_cubes'),
                denied_cubes=data.get('denied_cubes')
            )
        except:
            return []

        authorized = []

        for cube in cubes:
            cube_name = str(cube)

            if right.is_allowed(cube_name, self.allow_after_denied):
                authorized.append(cube)

        return authorized

    def restricted_cell(self, identity, cube, cell):
        data = self._rightRequest(identity, self.restricted_cell_method, cube.name)
        right = _DematAccessRight(
            cell_restrictions=data.get('cell_restrictions')
        )

        cuts = right.cell_restrictions.get(cube.name, [])

        # Append cuts for "any cube"
        any_cuts = right.cell_restrictions.get(ALL_CUBES_WILDCARD, [])
        if any_cuts:
            cuts += any_cuts

        if cuts:
            restriction_cuts = []
            for cut in cuts:
                if isinstance(cut, compat.string_type):
                    cut = cut_from_string(cut, cube)
                else:
                    cut = cut_from_dict(cut)
                cut.hidden = True
                restriction_cuts.append(cut)

            restriction = Cell(cube, restriction_cuts)
        else:
            restriction = Cell(cube)

        if cell:
            return cell & restriction
        else:
            return restriction

    def hierarchy_limits(self, identity, cube):
        data = self._rightRequest(identity, self.hierarchy_limits_method, cube)
        right = _DematAccessRight(
            hierarchy_limits=data.get('hierarchy_limits')
        )

        return right.hierarchy_limits.get(str(cube), [])
