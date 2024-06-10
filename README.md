@Component
public class OAuth2TokenRelayFilter extends ZuulFilter {

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    private OAuth2AuthorizedClientManager authorizedClientManager;

    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 1;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    @Override
    public Object run() {
        RequestContext ctx = RequestContext.getCurrentContext();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.getPrincipal() instanceof OAuth2User) {
            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
            String principalName = oauth2User.getName();

            OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                "okta", principalName);

            if (client != null && client.getAccessToken() != null) {
                if (client.getAccessToken().isExpired()) {
                    OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("okta")
                            .principal(principalName)
                            .build();

                    client = authorizedClientManager.authorize(authorizeRequest);
                }

                ctx.addZuulRequestHeader("Authorization", "Bearer " + client.getAccessToken().getTokenValue());
            }
        }
        return null;
    }
}
