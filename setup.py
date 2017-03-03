from setuptools import setup

setup(
    name='PyDySoFu',
    version='0.1',
    packages=['pydysofu'],
    package_dir={'': '.'},
    url='https://github.com/twsswt/pydysofu',
    license='',
    author='Tom Wallis, Tim Storer',
    author_email='twallisgm@gmail.com',
    description='Python Dynamic Source Fuzzing',
    setup_requires=[],
    test_suite='nose.collector',
    tests_require=['mock', 'nose']
)
