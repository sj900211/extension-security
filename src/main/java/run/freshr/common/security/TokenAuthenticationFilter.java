package run.freshr.common.security;

import static run.freshr.common.security.TokenProvider.signedId;
import static run.freshr.common.security.TokenProvider.signedRole;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import java.io.IOException;
import java.util.Arrays;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import run.freshr.common.data.ExceptionData;
import run.freshr.common.data.ExceptionsData;

/**
 * 토큰 인가 Filter
 *
 * @author FreshR
 * @apiNote 토큰 인가 Filter
 * @since 2024. 3. 29. 오전 10:58:15
 */
@Slf4j
@RequiredArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {

  private TokenProvider provider;
  private ExceptionsData exceptionsData;

  public TokenAuthenticationFilter(TokenProvider provider, ExceptionsData exceptionsData) {
    this.provider = provider;
    this.exceptionsData = exceptionsData;
  }

  /**
   * filter 프로세스
   *
   * @param request     request
   * @param response    response
   * @param filterChain filter chain
   * @apiNote {@link TokenProvider} 를 사용해서 인가 처리
   * @author FreshR
   * @since 2024. 3. 29. 오전 10:58:15
   */
  @Override
  protected void doFilterInternal(@NotNull HttpServletRequest request,
      @NotNull HttpServletResponse response, @NotNull FilterChain filterChain) {
    log.debug("**** SECURITY FILTER START");

    try {
      String accessToken = provider.extractToken(request);

      provider.setThreadLocal(accessToken);

      SecurityContextHolder.getContext().setAuthentication(provider.getAuthentication());

      log.debug("**** Role: " + signedRole.get().name());
      log.debug("**** Id: " + signedId.get());

      filterChain.doFilter(request, response);
    } catch (Exception e) {
      log.error("**** Exception ****");
      log.error("**** error message : " + e.getMessage());
      log.error("**** stack trace : " + Arrays.toString(e.getStackTrace()));
      log.error(e.getMessage(), e);

      SecurityContextHolder.clearContext();

      ExceptionData error = exceptionsData.getError();

      try {
        response.getWriter().write(provider.error(error));
      } catch (IOException ie) {
        log.error("**** IOException ****");
        log.error("**** error message : " + e.getMessage());
        log.error("**** stack trace : " + Arrays.toString(e.getStackTrace()));
        log.error(ie.getMessage(), ie);
      }

      response.setStatus(error.getHttpStatus().value());
    } finally {
      log.debug("**** SECURITY FILTER FINISH");
    }
  }

}
