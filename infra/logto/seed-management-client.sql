\set ON_ERROR_STOP on

-- Logto OSS deliberately has no unauthenticated Management API bootstrap
-- endpoint. This narrowly scoped, version-pinned seed creates one ephemeral
-- M2M client after Logto has initialized its schema. bootstrap.py removes the
-- client after reconciliation unless explicitly asked to retain it.
begin;
select pg_advisory_xact_lock(hashtext('hybrid-ndr-logto-bootstrap-client'));

do $$
begin
  if to_regclass('public.applications') is null
     or to_regclass('public.application_secrets') is null
     or to_regclass('public.applications_roles') is null then
    raise exception 'Logto 1.39 application tables are unavailable; seed Logto before bootstrapping';
  end if;

  if not exists (
    select 1 from public.roles
    where tenant_id = 'default'
      and name = 'Logto Management API access'
      and type = 'MachineToMachine'
  ) then
    raise exception 'Logto 1.39 Management API role is unavailable; seed Logto before bootstrapping';
  end if;

  if exists (
    select 1 from public.applications
    where id = 'hybrid-ndr-bootstrap'
      and (tenant_id <> 'default' or type <> 'MachineToMachine')
  ) then
    raise exception 'application ID hybrid-ndr-bootstrap is already used by an incompatible application';
  end if;
end
$$;

insert into public.applications (
  tenant_id,
  id,
  name,
  secret,
  description,
  type,
  oidc_client_metadata,
  custom_client_metadata,
  custom_data
)
values (
  'default',
  'hybrid-ndr-bootstrap',
  'Hybrid NDR ephemeral bootstrap',
  '#internal:' || md5(:'bootstrap_client_secret'),
  'Ephemeral Management API client created by the Hybrid NDR bootstrap',
  'MachineToMachine',
  '{"redirectUris":[],"postLogoutRedirectUris":[]}'::jsonb,
  '{}'::jsonb,
  '{"hybridNdrBootstrap":true,"schemaVersion":"logto-1.39"}'::jsonb
)
on conflict (id) do update set
  name = excluded.name,
  secret = excluded.secret,
  description = excluded.description,
  oidc_client_metadata = excluded.oidc_client_metadata,
  custom_client_metadata = excluded.custom_client_metadata,
  custom_data = excluded.custom_data;

insert into public.application_secrets (
  tenant_id,
  application_id,
  name,
  value,
  expires_at
)
values (
  'default',
  'hybrid-ndr-bootstrap',
  'Hybrid NDR ephemeral bootstrap',
  :'bootstrap_client_secret',
  now() + interval '15 minutes'
)
on conflict (tenant_id, application_id, name) do update set
  value = excluded.value,
  created_at = now(),
  expires_at = excluded.expires_at;

insert into public.applications_roles (tenant_id, id, application_id, role_id)
select
  'default',
  'hybrid-ndr-role-link',
  'hybrid-ndr-bootstrap',
  roles.id
from public.roles
where roles.tenant_id = 'default'
  and roles.name = 'Logto Management API access'
  and roles.type = 'MachineToMachine'
on conflict (tenant_id, application_id, role_id) do nothing;

commit;
