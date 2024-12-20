# Spring Boot 3.0.0 Tutorial - Cross-Origin Resource Sharing (CORS) & Spring Security
Spring Boot Cors
## Youtube
* video: https://www.youtube.com/watch?v=yOoiRMlu6u4
* CORS: https://developer.mozilla.org/en-US/d...
* CORS & Security: https://docs.spring.io/spring-securit...
* Github: https://github.com/wdkeyser02/SpringB...
* Github: https://github.com/wdkeyser02/SpringB...
* Github: https://github.com/wdkeyser02/SpringB...
* Subscribe: https://bit.ly/springboottutorial

## RealWorld-2024
* Since the popular browsers `Chrome` and `Edge` do not correctly display records of errors encountered (the official explanation of the browser is for security reasons), it makes debugging difficult for ordinary developers.
It does not expose and hide the behavior of the backend server, that is, the `fetch` action performed by `iniator`
* Firefox is recommended to debug the behavior .
### Key codes
   * Process the response javascript first judgment `OPTIONS` method
     ```java
     @Configuration
     public class SecurityConfig {
     (ommitted..)
       @Bean
       SecurityFilterChain securityFilterChain(HttpSecurity http ,
         (ommitted..)
         http
         (ommitted..)
            .csrf(AbstractHttpConfigurer::disable)
           .cors(configurationSource -> configurationSource
           .configurationSource(corsConfigurationSource()));
         return http.build();
       }
       @Bean // process javascript framewrok to ptrflight
       CorsConfigurationSource corsConfigurationSource() {
         CorsConfiguration configuration = new CorsConfiguration();
         configuration.setAllowCredentials(false); //process cookies 
         configuration.setAllowedOriginPatterns(List.of("*"));
         configuration.setAllowedOrigins(List.of("*"));
         configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTION"));
         configuration.setAllowedHeaders(Arrays.asList("X-idp", "Authorization", "Content-Type", "x-requested-with", "authorization",  "credential", "X-XSRF-TOKEN" ,"x-tenant-id"));
         configuration.setExposedHeaders(Arrays.asList("xsrf-token", "Content-Disposition"));
         UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
         source.registerCorsConfiguration("/**", configuration);
         return source;
       }
     }
     ```
     * Handle response javascript actual `POST` (other common is `GET`) method
     ```java
     public class CorsFilter implements Filter {
          protected static final String CONTENT_SECURITY_POLICY = Optional.ofNullable(System.getenv("CONTENT_SECURITY_POLICY"))
               .orElse("default-src 'self'; script-src 'self' https://trusted-cdn.com 'sha256-4IiDsMH+GkJlxivIDNfi6qk0O5HPtzyvNwVT3Wt8TIw='; style-src 'self' https://trusted-cdn.com; img-src 'self' https://trusted-cdn.com data:; connect-src 'self' https://api.trusted.com; font-src 'self' https://fonts.gstatic.com; media-src 'self'; manifest-src 'self'; worker-src 'self'; form-action 'self'; frame-src 'self'; frame-ancestors 'self'; object-src 'none';");
               
          protected static final String ALLOWED_ALL = Optional.ofNullable(System.getenv("ALLOWED_ORIGINS"))
               .orElse(Optional.ofNullable(System.getProperty("web.cors.allowOrigins")).orElse("*"));
               
          private AntPathMatcher matcher = new AntPathMatcher();

          @Override
          public void doFilter(ServletRequest req, ServletResponse resp, FilterChain filterChain)
            throws IOException, ServletException {
               HttpServletResponse response = (HttpServletResponse) resp;
               HttpServletRequest request = (HttpServletRequest) req;
               String method = request.getMethod();
               String origin = request.getHeader("Origin");

               if (matchesOrigins(origin , ALLOWED_ALL)) {
                   response.setHeader("Access-Control-Allow-Origin", origin);
               }

               response.setHeader("Access-Control-Allow-Methods", method);
  
               response.setHeader("Access-Control-Max-Age", "3600");

               Iterator<String> headerNames = request.getHeaderNames().asIterator();
               List<String> headerNamelList = new ArrayList<String>();
               headerNames.forEachRemaining(headerNamelList::add);
               String allowHeaders = StringUtils.join(headerNamelList ,',' );

               response.setHeader("Access-Control-Allow-Headers", allowHeaders);
               response.addHeader("Access-Control-Expose-Headers", "xsrf-token, Content-Disposition");
  
               response.setHeader("X-Content-Type-Options", "nosniff");
               response.setHeader("X-Frame-Options", "DENY");
               response.setHeader("X-XSS-Protection", "1; mode=block");
               response.setHeader("Content-Security-Policy", CONTENT_SECURITY_POLICY);
  

               if ("OPTIONS".equalsIgnoreCase(method)) {
                   response.setStatus(HttpServletResponse.SC_OK);
               } else {
                   filterChain.doFilter(req, resp);
               }
           }
           protected boolean matchesOrigins(final String requestOrigin , String allowedAll) {
               Set<String> allowedOrigins = Optional.ofNullable(allowedAll)
                      .map(origins -> Arrays.stream(origins.split(","))
                      .map(String::trim)
                      .filter(origin -> !origin.isEmpty())
                      .collect(Collectors.toSet()))
                      .orElse(new HashSet<>());

               if (allowedOrigins.contains(requestOrigin)) {
                   return true;
               }
               for(String env:allowedOrigins) {
                   if (matcher.match(env, requestOrigin)) {
                       return true;
                   }
               }
               return false ;
          }
     }
     ```