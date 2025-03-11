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
    author="Your Name",
    author_email="your.email@example.com",
    description="A CLI tool to check for API keys, credentials, and other security issues in your codebase.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/pycheck",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)