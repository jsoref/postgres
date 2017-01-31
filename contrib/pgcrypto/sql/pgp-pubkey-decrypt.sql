--
-- PGP Public Key Encryption
--

-- As most of the low-level stuff is tested in symmetric key
-- tests, here's only public-key specific tests

create table keytbl (
	id int4,
	name text,
	pubkey text,
	seckey text
);
create table encdata (
	id int4,
	data text
);

insert into keytbl (id, name, pubkey, seckey)
values (1, 'elg1024', '
-----BEGIN PGP PUBLIC KEY BLOCK-----
-----END PGP PUBLIC KEY BLOCK-----
', '
-----BEGIN PGP PRIVATE KEY BLOCK-----
-----END PGP PRIVATE KEY BLOCK-----
');

insert into keytbl (id, name, pubkey, seckey)
values (2, 'elg2048', '
-----BEGIN PGP PUBLIC KEY BLOCK-----
-----END PGP PUBLIC KEY BLOCK-----
', '
-----BEGIN PGP PRIVATE KEY BLOCK-----
-----END PGP PRIVATE KEY BLOCK-----
');

insert into keytbl (id, name, pubkey, seckey)
values (3, 'elg4096', '
-----BEGIN PGP PUBLIC KEY BLOCK-----
-----END PGP PUBLIC KEY BLOCK-----
', '
-----BEGIN PGP PRIVATE KEY BLOCK-----
-----END PGP PRIVATE KEY BLOCK-----
');

insert into keytbl (id, name, pubkey, seckey)
values (4, 'rsa2048', '
-----BEGIN PGP PUBLIC KEY BLOCK-----
-----END PGP PUBLIC KEY BLOCK-----
', '
-----BEGIN PGP PRIVATE KEY BLOCK-----
-----END PGP PRIVATE KEY BLOCK-----
');

insert into keytbl (id, name, pubkey, seckey)
values (5, 'psw-elg1024', '
-----BEGIN PGP PUBLIC KEY BLOCK-----
-----END PGP PUBLIC KEY BLOCK-----
', '
-----BEGIN PGP PRIVATE KEY BLOCK-----
-----END PGP PRIVATE KEY BLOCK-----
');

insert into keytbl (id, name, pubkey, seckey)
values (6, 'rsaenc2048', '
-----BEGIN PGP PUBLIC KEY BLOCK-----
-----END PGP PUBLIC KEY BLOCK-----
', '
-----BEGIN PGP PRIVATE KEY BLOCK-----
-----END PGP PRIVATE KEY BLOCK-----
');

insert into keytbl (id, name, pubkey, seckey)
values (7, 'rsaenc2048-psw', '
same key with password
', '
-----BEGIN PGP PRIVATE KEY BLOCK-----
-----END PGP PRIVATE KEY BLOCK-----
');


-- elg1024 / aes128
insert into encdata (id, data) values (1, '
-----BEGIN PGP MESSAGE-----
-----END PGP MESSAGE-----
');

-- elg2048 / blowfish
insert into encdata (id, data) values (2, '
-----BEGIN PGP MESSAGE-----
-----END PGP MESSAGE-----
');

-- elg4096 / aes256
insert into encdata (id, data) values (3, '
-----BEGIN PGP MESSAGE-----
-----END PGP MESSAGE-----
');

-- rsaenc2048 / aes128
insert into encdata (id, data) values (4, '
-----BEGIN PGP MESSAGE-----
-----END PGP MESSAGE-----
');

-- rsaenc2048 / aes128 (not from gnupg)
insert into encdata (id, data) values (5, '
-----BEGIN PGP MESSAGE-----
-----END PGP MESSAGE-----
');

-- successful decrypt
select pgp_pub_decrypt(dearmor(data), dearmor(seckey))
from keytbl, encdata where keytbl.id=1 and encdata.id=1;

select pgp_pub_decrypt(dearmor(data), dearmor(seckey))
from keytbl, encdata where keytbl.id=2 and encdata.id=2;

select pgp_pub_decrypt(dearmor(data), dearmor(seckey))
from keytbl, encdata where keytbl.id=3 and encdata.id=3;

select pgp_pub_decrypt(dearmor(data), dearmor(seckey))
from keytbl, encdata where keytbl.id=6 and encdata.id=4;

-- wrong key
select pgp_pub_decrypt(dearmor(data), dearmor(seckey))
from keytbl, encdata where keytbl.id=2 and encdata.id=1;

-- sign-only key
select pgp_pub_decrypt(dearmor(data), dearmor(seckey))
from keytbl, encdata where keytbl.id=4 and encdata.id=1;

-- rsa: password-protected secret key, wrong password
select pgp_pub_decrypt(dearmor(data), dearmor(seckey), '123')
from keytbl, encdata where keytbl.id=7 and encdata.id=4;

-- rsa: password-protected secret key, right password
select pgp_pub_decrypt(dearmor(data), dearmor(seckey), 'parool')
from keytbl, encdata where keytbl.id=7 and encdata.id=4;

-- password-protected secret key, no password
select pgp_pub_decrypt(dearmor(data), dearmor(seckey))
from keytbl, encdata where keytbl.id=5 and encdata.id=1;

-- password-protected secret key, wrong password
select pgp_pub_decrypt(dearmor(data), dearmor(seckey), 'foo')
from keytbl, encdata where keytbl.id=5 and encdata.id=1;

-- password-protected secret key, right password
select pgp_pub_decrypt(dearmor(data), dearmor(seckey), 'parool')
from keytbl, encdata where keytbl.id=5 and encdata.id=1;

-- test for a short read from prefix_init
select pgp_pub_decrypt(dearmor(data), dearmor(seckey))
from keytbl, encdata where keytbl.id=6 and encdata.id=5;
