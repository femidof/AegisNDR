const getCustomJwtClaims = async ({ token, context }) => {
  // Logto 1.39 exposes the issuing application to both user and client-
  // credential customizers. bootstrap.py writes this binding only on the two
  // AegisNDR applications, so unrelated applications remain untouched.
  const binding = context.application?.customData?.hybrid_ndr_binding;
  if (!binding) {
    return {};
  }

  const organizationId = binding.organization_id;
  const tenantId = binding.tenant_id;
  const deploymentIds = binding.deployment_ids;
  if (
    typeof organizationId !== 'string' ||
    typeof tenantId !== 'string' ||
    !Array.isArray(deploymentIds) ||
    deploymentIds.length === 0
  ) {
    throw new Error('AegisNDR application binding is incomplete');
  }

  const isMachine = token.kind === 'ClientCredentials';
  const roles = isMachine
    ? [binding.machine_role].filter((value) => typeof value === 'string')
    : (context.user?.organizationRoles ?? [])
      .filter((role) => role.organizationId === organizationId)
      .map(({ roleName }) => roleName);

  const sessionId = token.sessionUid ?? token.sid;
  if (!isMachine && (typeof sessionId !== 'string' || sessionId.length === 0)) {
    // Interactive API tokens must remain attributable to the browser session
    // whose session-bound refresh grant produced them.
    throw new Error('AegisNDR user access token has no Logto session binding');
  }

  return {
    // The API compares this signed application binding with Logto's built-in
    // organization_id. A token requested for another organization is rejected.
    organization_binding_id: organizationId,
    tenant_id: tenantId,
    deployment_ids: deploymentIds.filter((value) => typeof value === 'string'),
    roles,
    actor_type: isMachine ? 'machine' : 'human',
    ...(isMachine ? {} : { session_id: sessionId }),
  };
};
