from setuptools import setup, find_packages

setup(
    name="pardusguard",
    version="0.1.0",
    description="System Hardening & Security Assessment Tool for Pardus Linux",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    license="GPL-3.0",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "PyGObject>=3.42.0",
        "pycairo>=1.20.0",
        "reportlab>=4.0",
    ],
    entry_points={
        "console_scripts": [
            "pardusguard=src.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: X11 Applications :: GTK",
        "Intended Audience :: End Users/Desktop",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
)
