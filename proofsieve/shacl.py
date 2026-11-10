"""Validate inline Turtle against the guard's restricted SHACL Core profile."""

import base64
import logging
import re
from collections.abc import Callable
from contextvars import ContextVar

from pyshacl import validate
from rdflib import Graph, Literal, URIRef
from rdflib.exceptions import ParserError
from rdflib.namespace import RDF, SH, XSD
from rdflib.plugins.parsers.notation3 import RDFSink, SinkParser, decimal_syntax, exponent_syntax, integer_syntax

from .json_numbers import MAX_JSON_NUMBER_LENGTH


MAX_TURTLE_BYTES = 64 * 1024
MAX_SHAPE_TRIPLES = 256
MAX_DATA_TRIPLES = 4096

_PROPERTY_CONSTRAINTS = {SH.hasValue, SH.minCount, SH.maxCount, SH.datatype, SH.nodeKind}
_NODE_KINDS = {SH.IRI, SH.Literal, SH.BlankNode, SH.BlankNodeOrIRI, SH.BlankNodeOrLiteral, SH.IRIOrLiteral}
_INTEGER_LEXICAL = re.compile(r"[+-]?[0-9]+")
_DECIMAL_LEXICAL = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)")
_FLOAT_LEXICAL = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")
_XSD_WHITESPACE = str.maketrans("", "", " \r\n\t")
_TURTLE_NUMBERS = ((exponent_syntax, XSD.double), (decimal_syntax, XSD.decimal), (integer_syntax, XSD.integer))
_XSD_INTEGER_TYPES = {
    XSD.integer, XSD.long, XSD.int, XSD.short, XSD.byte,
    XSD.unsignedLong, XSD.unsignedInt, XSD.unsignedShort, XSD.unsignedByte,
    XSD.positiveInteger, XSD.nonNegativeInteger, XSD.negativeInteger, XSD.nonPositiveInteger,
}
_TURTLE_PARSE = ContextVar("proofsieve_turtle_parse", default=False)

# RDFLib can include a malformed literal or IRI in its diagnostics.
logging.getLogger("rdflib.term").addFilter(lambda _: not _TURTLE_PARSE.get())


class _BoundedGraph(Graph):
    def __init__(self, max_triples):
        super().__init__()
        self.max_triples = max_triples

    def add(self, triple):
        value = triple[2]
        if isinstance(value, Literal) and value.ill_typed is True:
            raise ValueError("Ill-typed RDF literal")
        if len(self) >= self.max_triples and triple not in self:
            raise ValueError("Turtle graph exceeds the triple limit")
        return super().add(triple)


class _TurtleSink(RDFSink):
    def newLiteral(self, s, dt=None, lang=None):
        # SHACL compares RDF terms, so keep their original lexical form.
        if dt is not None and lang is not None:
            raise ValueError("An RDF literal cannot have both a datatype and a language tag")
        if dt == XSD.boolean and s not in {"true", "false", "1", "0"}:
            raise ValueError("Invalid RDF boolean literal")
        if dt in {XSD.normalizedString, XSD.token} and any(c in s for c in "\r\n\t"):
            raise ValueError("Invalid whitespace in RDF string literal")
        if dt == XSD.token and (s != s.strip(" ") or "  " in s):
            raise ValueError("Invalid spacing in RDF token literal")
        if dt in _XSD_INTEGER_TYPES or dt in {XSD.decimal, XSD.float, XSD.double}:
            lexical = s.strip(" \r\n\t")
            if dt in _XSD_INTEGER_TYPES:
                valid = _INTEGER_LEXICAL.fullmatch(lexical)
            elif dt == XSD.decimal:
                valid = _DECIMAL_LEXICAL.fullmatch(lexical)
            else:
                valid = lexical in {"INF", "-INF", "NaN"} or _FLOAT_LEXICAL.fullmatch(lexical)
            if len(lexical) > MAX_JSON_NUMBER_LENGTH or not valid:
                raise ValueError("Invalid or oversized RDF numeric literal")
        if dt == XSD.base64Binary:
            encoded = s.translate(_XSD_WHITESPACE).encode("ascii")
            if base64.b64encode(base64.b64decode(encoded, validate=True)) != encoded:
                raise ValueError("Invalid RDF base64Binary literal")
        if dt in {RDF.XMLLiteral, RDF.HTML}:
            raise ValueError("Embedded XML and HTML literals are outside the SHACL profile")
        if dt is None and lang is None:
            dt = XSD.string
        return Literal(s, datatype=dt, lang=lang, normalize=False)


class _TurtleParser(SinkParser):
    def nodeOrLiteral(self, argstr, i, res):
        # RDFLib normally converts shorthand numbers to Python values before building the term.
        start = self.skipSpace(argstr, i)
        if start < 0:
            return -1
        for syntax, datatype in _TURTLE_NUMBERS:
            match = syntax.match(argstr, start)
            if match is not None:
                res.append(self._store.newLiteral(match.group(), datatype))
                return match.end()
        return super().nodeOrLiteral(argstr, start, res)


def _parse_turtle(text: str, label: str, max_triples: int) -> Graph:
    if not isinstance(text, str):
        raise ValueError(f"{label} must be a Turtle string")
    try:
        if len(text) > MAX_TURTLE_BYTES or len(text.encode("utf-8")) > MAX_TURTLE_BYTES:
            raise ValueError(f"{label} exceeds the Turtle size limit")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} is not valid UTF-8 text") from exc

    graph = _BoundedGraph(max_triples)
    context = _TURTLE_PARSE.set(True)
    try:
        # Match RDFLib's TurtleParser with an inline buffer and a validating sink.
        _TurtleParser(_TurtleSink(graph), baseURI="https://proofsieve.invalid/", turtle=True).loadBuf(text)
    except (ParserError, SyntaxError, ValueError, RecursionError, IndexError, OverflowError,
            AssertionError, AttributeError):
        # RDFLib parser exceptions can include a fragment of the input.
        raise ValueError(f"{label} is invalid or outside the supported Turtle limits") from None
    finally:
        _TURTLE_PARSE.reset(context)
    return graph


def _check_shape_terms(graph: Graph, shape, shape_type: URIRef, allowed: set) -> None:
    for predicate, value in graph.predicate_objects(shape):
        if predicate == RDF.type:
            if value != shape_type:
                raise ValueError("shape has an unsupported RDF type")
        elif predicate not in allowed:
            raise ValueError("shape uses a predicate outside the supported SHACL Core profile")


def _check_property_shape(graph: Graph, shape, targeted: bool) -> None:
    allowed = _PROPERTY_CONSTRAINTS | {SH.path}
    if targeted:
        allowed |= {SH.targetNode}
    _check_shape_terms(graph, shape, SH.PropertyShape, allowed)

    paths = list(graph.objects(shape, SH.path))
    if len(paths) != 1 or not isinstance(paths[0], URIRef):
        raise ValueError("property shape must have one IRI path")

    bounds = {}
    has_constraint = False
    for predicate in _PROPERTY_CONSTRAINTS:
        values = list(graph.objects(shape, predicate))
        if not values:
            continue
        has_constraint = True
        if predicate == SH.hasValue:
            if not all(isinstance(value, (URIRef, Literal)) for value in values):
                raise ValueError("sh:hasValue requires an IRI or literal")
            continue
        if len(values) != 1:
            raise ValueError("property shape repeats a single-valued constraint")
        value = values[0]
        if predicate in {SH.minCount, SH.maxCount}:
            if not isinstance(value, Literal) or value.datatype != XSD.integer:
                raise ValueError("SHACL counts must be nonnegative integers")
            count = value.toPython()
            if type(count) is not int or count < 0:
                raise ValueError("SHACL counts must be nonnegative integers")
            bounds[predicate] = count
        elif predicate == SH.datatype and not isinstance(value, URIRef):
            raise ValueError("sh:datatype requires an IRI")
        elif predicate == SH.nodeKind and value not in _NODE_KINDS:
            raise ValueError("sh:nodeKind requires a supported SHACL node kind")

    if not has_constraint:
        raise ValueError("property shape must have at least one supported constraint")
    if SH.maxCount in bounds and bounds.get(SH.minCount, 0) > bounds[SH.maxCount]:
        raise ValueError("property shape minimum count exceeds maximum count")


def compile_shapes(policy: str) -> Callable[[str], bool]:
    """Compile explicit node targets with direct IRI property paths and basic constraints."""
    shapes = _parse_turtle(policy, "SHACL policy", MAX_SHAPE_TRIPLES)
    target_pairs = list(shapes.subject_objects(SH.targetNode))
    if not target_pairs or any(not isinstance(target, URIRef) for _, target in target_pairs):
        raise ValueError("SHACL policy must declare explicit sh:targetNode IRIs")

    roots = {shape for shape, _ in target_pairs}
    property_shapes = set()
    for shape in roots:
        if (shape, SH.path, None) in shapes:
            _check_property_shape(shapes, shape, targeted=True)
        else:
            _check_shape_terms(shapes, shape, SH.NodeShape, {SH.targetNode, SH.property})
            properties = set(shapes.objects(shape, SH.property))
            if not properties or properties & roots:
                raise ValueError("node shape must reference property shapes without targets")
            property_shapes.update(properties)

    for shape in property_shapes:
        _check_property_shape(shapes, shape, targeted=False)
    if set(shapes.subjects()) - roots - property_shapes:
        raise ValueError("SHACL policy contains triples outside the targeted shapes")

    targets = frozenset(target for _, target in target_pairs)
    shape_triples = tuple(shapes)

    def check(data: str) -> bool:
        graph = _parse_turtle(data, "RDF data", MAX_DATA_TRIPLES)
        if any((target, None, None) not in graph for target in targets):
            return False

        # pySHACL adds system triples to its shapes graph. Use a request-local copy.
        request_shapes = Graph()
        for triple in shape_triples:
            request_shapes.add(triple)
        conforms, _, _ = validate(
            graph,
            shacl_graph=request_shapes,
            inference="none",
            do_owl_imports=False,
            advanced=False,
            js=False,
            abort_on_first=True,
        )
        return conforms is True

    return check
