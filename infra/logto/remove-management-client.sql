\set ON_ERROR_STOP on

begin;
select pg_advisory_xact_lock(hashtext('hybrid-ndr-logto-bootstrap-client'));

-- The custom-data marker prevents this cleanup from deleting an application
-- that merely collided with the stable bootstrap identifier.
delete from public.applications
where tenant_id = 'default'
  and id = 'hybrid-ndr-bootstrap'
  and custom_data @> '{"hybridNdrBootstrap":true,"schemaVersion":"logto-1.39"}'::jsonb;

commit;
