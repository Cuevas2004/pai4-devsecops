#!/usr/bin/env python3
"""Convierte el JSON de OWASP Dependency-Check al XML que importa DefectDojo.

El parser `Dependency Check Scan` de DefectDojo solo acepta XML. El pipeline
genera JSON (lo usa tambien el quality gate), asi que antes de importar se
traduce a un XML equivalente con los campos que el parser necesita.
"""
import json
import xml.etree.ElementTree as ET

NAMESPACE = "https://jeremylong.github.io/DependencyCheck/dependency-check.2.0.xsd"
ET.register_namespace("", NAMESPACE)

CVSS_V3_FIELDS = (
    "baseScore",
    "attackVector",
    "attackComplexity",
    "privilegesRequired",
    "userInteraction",
    "scope",
    "confidentialityImpact",
    "integrityImpact",
    "availabilityImpact",
    "exploitabilityScore",
    "impactScore",
)


def _tag(name):
    return f"{{{NAMESPACE}}}{name}"


def _sub(parent, name, text=None, **attrs):
    node = ET.SubElement(parent, _tag(name), attrs)
    if text is not None:
        node.text = str(text)
    return node


def _add_cvss(parent, name, data):
    if not isinstance(data, dict):
        return
    node = _sub(parent, name)
    if data.get("version"):
        _sub(node, "version", data["version"])
    for field in CVSS_V3_FIELDS:
        if data.get(field) is not None:
            _sub(node, field, data[field])


def _add_references(parent, references):
    if not references:
        return
    node = _sub(parent, "references")
    for reference in references:
        if isinstance(reference, str):
            reference = {"url": reference, "name": reference}
        ref = _sub(node, "reference")
        _sub(ref, "source", reference.get("source", ""))
        _sub(ref, "url", reference.get("url", ""))
        _sub(ref, "name", reference.get("name", reference.get("url", "")))


def json_to_xml(data):
    """Devuelve los bytes del XML equivalente al informe JSON."""
    root = ET.Element(_tag("analysis"))
    project = data.get("projectInfo") or {}
    project_node = _sub(root, "projectInfo")
    _sub(project_node, "name", project.get("name", "juice-shop"))
    if project.get("reportDate"):
        _sub(project_node, "reportDate", project["reportDate"])

    dependencies_node = _sub(root, "dependencies")
    for dependency in data.get("dependencies") or []:
        dep_node = _sub(dependencies_node, "dependency")
        _sub(dep_node, "fileName", dependency.get("fileName", ""))
        _sub(dep_node, "filePath", dependency.get("filePath", ""))

        packages = dependency.get("packages") or []
        if packages and packages[0].get("id"):
            identifiers = _sub(dep_node, "identifiers")
            package_node = _sub(identifiers, "package")
            _sub(package_node, "id", packages[0]["id"])

        vulnerabilities = dependency.get("vulnerabilities") or []
        if not vulnerabilities:
            continue
        vulns_node = _sub(dep_node, "vulnerabilities")
        for vulnerability in vulnerabilities:
            if not vulnerability.get("name"):
                continue
            vuln_node = _sub(
                vulns_node,
                "vulnerability",
                source=vulnerability.get("source", "NVD"),
            )
            _sub(vuln_node, "name", vulnerability["name"])
            _sub(vuln_node, "severity", vulnerability.get("severity", "medium"))
            _sub(vuln_node, "description", vulnerability.get("description", ""))
            if vulnerability.get("notes"):
                _sub(vuln_node, "notes", vulnerability["notes"])

            cwes = vulnerability.get("cwes") or []
            if cwes:
                cwes_node = _sub(vuln_node, "cwes")
                for cwe in cwes:
                    _sub(cwes_node, "cwe", cwe)

            _add_cvss(vuln_node, "cvssV3", vulnerability.get("cvssv3"))
            _add_cvss(vuln_node, "cvssV2", vulnerability.get("cvssv2"))
            _add_references(vuln_node, vulnerability.get("references"))

    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def convert_file(source, destination):
    data = json.loads(source.read_text(encoding="utf-8"))
    destination.write_bytes(json_to_xml(data))
    return destination
