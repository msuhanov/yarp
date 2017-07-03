from distutils.core import setup
from yarp import __version__

setup(
	name = 'yarp',
	version = __version__,
	license = 'GPLv3',
	packages = [ 'yarp' ],
	scripts = [ 'yarp-carver', 'yarp-print', 'yarp-timeline' ],
	description = 'Yet another registry parser',
	author = 'Maxim Suhanov',
	author_email = 'no.spam.c@mail.ru',
	classifiers = [
		'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
		'Operating System :: OS Independent',
		'Programming Language :: Python :: 3',
		'Development Status :: 4 - Beta'
	]
)
