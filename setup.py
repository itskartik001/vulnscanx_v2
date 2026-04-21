from setuptools import setup, find_packages
setup(
    name="vulnscanx",
    version="2.0.0",
    packages=find_packages(),
    entry_points={"console_scripts": ["vulnscanx=cli.main:main"]},
    python_requires=">=3.9",
)
