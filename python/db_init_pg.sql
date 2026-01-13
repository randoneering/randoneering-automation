

create user svc_ansible_user with password '{{ svc_ansible_password }}';
grant rds_superuser to svc_ansible_user;

do $block$
declare
  _missing bool;
begin
  select (count(*) filter (where rolname = 'dba')) = 0 into strict _missing from pg_roles;
  if _missing then
      create role dba CREATEDB CREATEROLE LOGIN;
      grant rds_superuser to dba;
  end if
  ;
end;
$block$;



grant dba to master_user, svc_ansible_user;
create schema if not exists dba authorization dba;
revoke dba from master_user, svc_ansible_user;


do $block$
declare
    _missing bool;
begin
    select (count(*) filter (where rolname = 'readonly')) = 0 into strict _missing from pg_roles;
    if _missing then
        create role readonly nologin;
    end if
    ;
end;
$block$;
do $block$
declare
    _missing bool;
begin
    select (count(*) filter (where rolname = 'readwrite')) = 0 into strict _missing from pg_roles;
    if _missing then
        create role readwrite nologin;
    end if
    ;
end;
$block$;

do $block$
declare
    _missing bool;
begin
    select (count(*) filter (where usename = '{{ sevice_user }}')) = 0 into strict _missing from pg_user;
    if _missing then
        create user {{ sevice_user }} with password '{{ service_user_pass }}';
        grant {{ sevice_user }} to dba;
    else
        alter user {{ sevice_user }} with password '{{ service_user_pass }}';
    end if
    ;
end;
$block$ ;

grant {{ sevice_user }} to master_user;


create schema if not exists {{ schema_name }} authorization {{ sevice_user }};
grant {{ sevice_user }} to master_user;
grant {{ sevice_user }} to svc_ansible_user;
alter user {{ sevice_user }} set search_path to {{ schema_name }};

alter database {{ database_name }} owner to {{ sevice_user }};
grant connect on database {{ database_name }} to {{ sevice_user }};
grant usage on schema {{ schema_name }} to {{ sevice_user }};
grant create on database {{ database_name }} to {{ sevice_user }};
grant execute on all functions in schema {{ schema_name }} to {{ sevice_user }};
grant execute on all procedures in schema {{ schema_name }} to {{ sevice_user }};
grant all privileges on all sequences in schema {{ schema_name }} to {{ sevice_user }};
grant select, insert, update, truncate, delete on all tables in schema {{ schema_name }} to {{ sevice_user }};



grant usage on schema {{ schema_name }} to readonly, readwrite;
grant select on all tables in schema {{ schema_name }} to readonly, readwrite;
grant insert, update, delete on all tables in schema {{ schema_name }} to readwrite;
grant all privileges on all sequences in schema {{ schema_name }} to readwrite;
grant execute on all functions in schema {{ schema_name }} to readwrite;




alter default privileges for user {{ sevice_user }} grant select on tables to readonly;
alter default privileges for user {{ sevice_user }} grant usage on sequences to readonly;
alter default privileges for user {{ sevice_user }} grant usage on types to readonly;
alter default privileges for user {{ sevice_user }} grant select,insert,update,delete on tables to readwrite;
alter default privileges for user {{ sevice_user }} grant all privileges on sequences to readwrite;
alter default privileges for user {{ sevice_user }} grant execute on functions to readwrite;
alter default privileges for user {{ sevice_user }} grant usage on types to readwrite;


create user randoneering with password '{{ randoneering_password }}';

grant dba to randoneering;
