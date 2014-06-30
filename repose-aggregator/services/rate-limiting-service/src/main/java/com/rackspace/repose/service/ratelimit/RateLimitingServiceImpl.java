package com.rackspace.repose.service.ratelimit;

import com.rackspace.repose.service.limits.schema.HttpMethod;
import com.rackspace.repose.service.limits.schema.RateLimitList;
import com.rackspace.repose.service.limits.schema.TimeUnit;
import com.rackspace.repose.service.ratelimit.cache.CachedRateLimit;
import com.rackspace.repose.service.ratelimit.cache.RateLimitCache;
import com.rackspace.repose.service.ratelimit.config.*;
import com.rackspace.repose.service.ratelimit.exception.OverLimitException;
import com.rackspace.repose.service.ratelimit.util.StringUtilities;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class RateLimitingServiceImpl implements RateLimitingService {

    private static final Logger LOG = org.slf4j.LoggerFactory.getLogger(RateLimitingServiceImpl.class);
    private final RateLimitCache cache;
    private final RateLimitingConfigHelper helper;
    private final boolean useCaptureGroups;

    private RateLimiter rateLimiter;

    public RateLimitingServiceImpl(RateLimitCache cache, RateLimitingConfiguration rateLimitingConfiguration) {

        if (rateLimitingConfiguration == null) {
            throw new IllegalArgumentException("Rate limiting configuration must not be null.");
        }

        this.cache = cache;
        this.rateLimiter = new RateLimiter(cache);
        this.helper = new RateLimitingConfigHelper(rateLimitingConfiguration);
        useCaptureGroups = rateLimitingConfiguration.isUseCaptureGroups();
    }

    @Override
    public RateLimitList queryLimits(String user, List<String> groups) {

        if (StringUtilities.isBlank(user)) {
            throw new IllegalArgumentException("User required when querying rate limits.");
        }

        final Map<String, CachedRateLimit> cachedLimits = cache.getUserRateLimits(user);
        final ConfiguredLimitGroup configuredLimitGroup = helper.getConfiguredGroupByRole(groups);
        final RateLimitListBuilder limitsBuilder = new RateLimitListBuilder(cachedLimits, configuredLimitGroup);

        return limitsBuilder.toRateLimitList();
    }

    @Override
    public void trackLimits(String user, List<String> groups, String uri, Map<String, String[]> parameterMap, String httpMethod, int datastoreWarnLimit) throws OverLimitException {

        if (StringUtilities.isBlank(user)) {
            throw new IllegalArgumentException("User required when tracking rate limits.");
        }

        final ConfiguredLimitGroup configuredLimitGroup = helper.getConfiguredGroupByRole(groups);
        final List< Pair<String, ConfiguredRatelimit> > matchingConfiguredLimits = new ArrayList< Pair<String, ConfiguredRatelimit> >();
        TimeUnit largestUnit = null;

        // Go through all of the configured limits for this group
        for (ConfiguredRatelimit rateLimit : configuredLimitGroup.getLimit()) {
            Matcher uriMatcher;
            if (rateLimit instanceof ConfiguredRateLimitWrapper) {
                uriMatcher = ((ConfiguredRateLimitWrapper) rateLimit).getRegexPattern().matcher(uri);
            } else {
                LOG.error("Unable to locate pre-built regular expression pattern in for limit group.  This state is not valid. "
                        + "In order to continue operation, rate limiting will compile patterns dynamically.");
                uriMatcher = Pattern.compile(rateLimit.getUriRegex()).matcher(uri);
            }

            // Did we find a limit that matches the incoming uri and http method?
            List<Matcher> queryParamMatchers = getQueryParamMatchers(rateLimit.getQueryParam(), parameterMap);
            if (uriMatcher.matches() && httpMethodMatches(rateLimit.getHttpMethods(), httpMethod) && queryParamMatchers != null) {
                matchingConfiguredLimits.add(Pair.of(LimitKey.getLimitKey(configuredLimitGroup.getId(),
                        rateLimit.getId(), uriMatcher, queryParamMatchers, useCaptureGroups), rateLimit));

                if (largestUnit == null || rateLimit.getUnit().compareTo(largestUnit) > 0) {
                    largestUnit = rateLimit.getUnit();
                }
            }
        }
        if (matchingConfiguredLimits.size() > 0) {
            rateLimiter.handleRateLimit(user, matchingConfiguredLimits, largestUnit, datastoreWarnLimit);
        }
    }

    private boolean httpMethodMatches(List<HttpMethod> configMethods, String requestMethod) {
        return configMethods.contains(HttpMethod.ALL) || configMethods.contains(HttpMethod.valueOf(requestMethod.toUpperCase()));
    }

    /**
     *
     * @param configuredQueryParams A <code>List</code> of the configured query parameter regexes.
     * @param requestParameterMap A <code>Map</code> of the key/value pairs in the request.
     * @return Returns a <code>List</code> of <code>Matcher</code> if the configured query parameters are all matched
     *         against the request query parameters. Otherwise, <code>null</code> is returned.
     */
    private List<Matcher> getQueryParamMatchers(List<QueryParam> configuredQueryParams, Map<String, String[]> requestParameterMap) {
        // TODO: Allow for multiple values in the XSD to match against

        List<Matcher> matchingMatchers = new ArrayList<>();
        
        for (QueryParam configuredQueryParam : configuredQueryParams) {
            boolean paramMatchFound = false;
            Pattern configuredKeyPattern = Pattern.compile(configuredQueryParam.getKeyRegex());
            Pattern configuredValuePattern = Pattern.compile(configuredQueryParam.getValueRegex());

            for (Map.Entry<String, String[]> requestParam : requestParameterMap.entrySet()) {
                Matcher keyMatcher = configuredKeyPattern.matcher(decodeQueryString(requestParam.getKey()));

                if (keyMatcher.matches()) {
                    boolean valueMatchFound = false;

                    for (String requestValue : requestParam.getValue()) {
                        Matcher valueMatcher = configuredValuePattern.matcher(decodeQueryString(requestValue));

                        if (valueMatcher.matches()) {
                            matchingMatchers.add(valueMatcher);
                            paramMatchFound = true;
                            valueMatchFound = true;
                        }
                    }

                    if (valueMatchFound) { matchingMatchers.add(keyMatcher); }
                }
            }

            if (!paramMatchFound) { return null; }
        }

        return matchingMatchers;
    }

    private String decodeQueryString(String queryString) {
        String processedQueryString = queryString;

        try {
            processedQueryString = URLDecoder.decode(processedQueryString, "UTF-8");
        } catch (UnsupportedEncodingException uee) {
            /* Since we've hardcoded the UTF-8 encoding, this should never occur. */
            LOG.error("RateLimitingService.decodeQueryString - Unsupported Encoding", uee);
        }

        return processedQueryString;
    }
}
