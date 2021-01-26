import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="powerprotect",  # Replace with your own username
    version="0.1.0",
    author="Brad Soper",
    author_email="bradley.soper@dell.com",
    description="PowerProtect Python Class",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/EMC-Underground/powerprotect",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
