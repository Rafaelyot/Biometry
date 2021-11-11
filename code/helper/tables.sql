create table if not exists users
(
    id                   integer primary key,
    username             text not null unique,
    email                text not null unique,
    master_password      blob not null,
    master_password_salt blob not null
);


create table if not exists accounts
(
    id                        integer primary key,
    user_id                   integer,
    username                  text not null,
    email                     text not null,
    password                  blob not null,
    password_tag              blob not null,
    authenticator             text not null,
    private_key               blob,
    private_key_ttl           real,
    private_key_password_salt blob,
    public_key_id             integer,
    first_authentication      INTEGER default 1,
    foreign key (user_id) references users (id),
    unique (username, email, authenticator)
);