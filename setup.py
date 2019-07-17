from distutils.core import setup

name = 'pyactivedirectory'
version = '0.1.3'
setup(
  name=f'{name}',
  packages=[f'{name}'],  # this must be the same as the name above
  version=f'{version}',
  description='Module for work with active directory',
  author='Sheludchenkov Aleksey',
  author_email='aleshkashell@gmail.com',
  url='https://github.com/aleshkashell/pyactivedirectory',
  download_url=f'https://github.com/aleshkashell/pyactivedirectory/tarball/{version}',
  keywords=['active directory', 'AD', 'ldap'],
  classifiers=[],
  install_requires=[
          'ldap3',
      ],
)
