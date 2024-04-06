from setuptools import setup, find_packages

setup(name="Zero-Knowledge",
      version=1,
      packages=find_packages(),
      install_requires=open("requirements.txt", "r", encoding="utf-8").read().splitlines(),
      description='"Zero-Knowledge" Proof Implementation with HMAC Communication Implementation in Pure Python',
      long_description=open("README.md", "r", encoding="utf-8").read(),
      long_description_content_type="text/markdown",
      author="zk-Call",
      author_email="contact@zkcall.net",
      url="https://github.com/zk-Call",
      classifiers=[
          "License :: OSI Approved :: MIT License",
          "Topic :: Security :: Cryptography",
      ]
      )
