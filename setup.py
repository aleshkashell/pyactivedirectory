from distutils.core import setup
setup(
  name='pyactivedirectory',
  packages=['pyactivedirectory'],  # this must be the same as the name above
  version='0.1.0',
  description='Module for work with active directory',
  author='Sheludchenkov Aleksey',
  author_email='aleshkashell@gmail.com',
  url='https://github.com/aleshkashell/pyactivedirectory',
  download_url='https://github.com/aleshkashell/pyactivedirectory/tarball/0.1.0',
  keywords=['active directory', 'AD', 'ldap'],
  classifiers=[],
  install_requires=[
          'ldap3',
      ],
)
