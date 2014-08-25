USE mysql;

DROP FUNCTION IF EXISTS lib_mysqludf_fields_sha1_info;
CREATE FUNCTION lib_mysqludf_fields_sha1_info RETURNS STRING SONAME 'lib_mysqludf_fields_sha1.so';

DROP FUNCTION IF EXISTS fields_sha1;
CREATE FUNCTION fields_sha1 RETURNS STRING SONAME 'lib_mysqludf_fields_sha1.so';

