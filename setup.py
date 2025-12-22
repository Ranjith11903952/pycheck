from setuptools import setup, find_packages

setup(
    name="pycheck",
    version="0.1",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'pycheck=pycheck.cli:main',
        ],
    },
)

