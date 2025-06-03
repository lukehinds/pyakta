from setuptools import setup, find_packages

setup(
    name="pyakta",
    version="0.1.0",
    packages=find_packages(include=["pyakta", "pyakta.*"]),
    description="Library for Akta",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Luke Hinds",
    author_email="lukehinds@gmail.com",
    url="https://github.com/lukehinds/pyakta",
    install_requires=[
        # Add your project dependencies here, e.g.:
        # 'requests>=2.20',
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
)
