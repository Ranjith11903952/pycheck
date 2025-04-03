from setuptools import setup, find_packages

setup(
    name="pycheck",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        # Add any dependencies here
    ],
    entry_points={
        'console_scripts': [
            'pycheck=pycheck.cli:main',
        ],
    },
)
