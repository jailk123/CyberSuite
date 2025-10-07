from setuptools import setup, find_packages

setup(
    name="CyberSuite",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'rich',
        'requests',
        'shodan',
        'watchdog',
        'customtkinter',
    ],
    entry_points={
        'console_scripts': [
            'cybersuite=cli.main_cli:main',
        ],
    },
)
