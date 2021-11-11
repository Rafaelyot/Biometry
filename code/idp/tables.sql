create table if not exists users
(
    id       integer primary key,
    username text not null unique,
    email    text not null unique,
    password blob not null
);


create table if not exists public_key
(
    id                 integer primary key,
    user_id            integer,
    public_key_content blob,
    public_key_ttl     real,
    foreign key (user_id) references users (id)
);