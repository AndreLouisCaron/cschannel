============================================================
`cschannel` --- Streaming Microsoft SChannel wrapper in C.
============================================================
:authors:
   Andre Caron
:contact: andre.l.caron@gmail.com

Description
===========

This library is a `facade`_ for the horrible Micrsoft SChannel (SSL/TLS) API.
The SChannel API is actually the SSPI API with a few nitpicks.  Because it aims
at being the most generalized interface possible to all forms of cryptographic
channels, it is rather painful to use.  The ``cschannel`` project aims at making
SChannel-enabled applications easier.

Documentation
=============

The project uses `Doxygen`_ to publish API documentation.  Builds for key
versions are available online:

* `latest <http://andrelouiscaron.github.com/cschannel/latest/>`_

For other commits, run the ``doxygen`` command from the root of the source tree.

.. _`facade`: http://en.wikipedia.org/wiki/Facade_pattern
.. _`Doxygen`: http://www.stack.nl/~dimitri/doxygen/
