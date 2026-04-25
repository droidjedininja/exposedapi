[project]
name = "exposedapi"
version = "0.1.0"
description = "API misconfiguration scanner for pentesters"
authors = [{ name="You" }]
readme = "README.md"
requires-python = ">=3.8"
dependencies = [
    "requests"
]

[project.scripts]
exposedapi = "exposedapi.cli:main"

[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"
