from setuptools import setup, find_packages

setup(
    name="pycheck",
    version="0.1",
    packages=find_packages(),  # Automatically find the 'pycheck' package
    install_requires=[
        # Add any dependencies here
    ],
    entry_points={
        'console_scripts': [
            'pycheck=pycheck.cli:main',
        ],
    },
    author="Ranjith11903952",
    author_email="v.sairanjith11903952@gmail.com",
    description="A CLI tool to check for API keys, credentials, and other security issues in your codebase.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Ranjith11903952/pycheck",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
