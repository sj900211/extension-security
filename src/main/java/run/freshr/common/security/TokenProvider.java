package run.freshr.common.security;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.security.core.authority.AuthorityUtils.createAuthorityList;
import static org.springframework.util.StringUtils.hasLength;
import static run.freshr.domain.auth.enumerations.Role.ROLE_ANONYMOUS;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import run.freshr.common.data.EntityData;
import run.freshr.common.data.ExceptionData;
import run.freshr.common.data.ResponseData;
import run.freshr.common.exceptions.UnAuthenticatedException;
import run.freshr.common.utils.JwtUtil;
import run.freshr.domain.auth.enumerations.Role;
import run.freshr.domain.auth.redis.AccessRedis;
import run.freshr.domain.auth.unit.redis.AccessRedisUnit;
import run.freshr.domain.auth.unit.redis.RefreshRedisUnit;

/**
 * Token 관리 기능 정의
 *
 * @author FreshR
 * @apiNote Token 관리 기능 정의
 * @since 2024. 3. 29. 오전 10:02:53
 */
@Component
@RequiredArgsConstructor
public class TokenProvider {

  private final AccessRedisUnit accessRedisUnit;
  private final RefreshRedisUnit refreshRedisUnit;

  private final EntityData entityData;

  private final ObjectMapper objectMapper;

  public static ThreadLocal<String> signedId = new ThreadLocal<>(); // 요청한 토큰의 계정 일련 번호
  public static ThreadLocal<Role> signedRole = new ThreadLocal<>(); // 요청한 토큰의 계정 권한

  public static final String BEARER_PREFIX = "Bearer ";

  /**
   * 접근 토큰 발급
   *
   * @param id id
   * @return string
   * @apiNote 접근 토큰 발급
   * @author FreshR
   * @since 2024. 3. 29. 오전 10:03:07
   */
  public String generateAccessToken(final String id) {
    return JwtUtil.generate(id, entityData.getAccessExpiration());
  }

  /**
   * 갱신 토큰 발급
   *
   * @param id id
   * @return string
   * @apiNote 갱신 토큰 발급
   * @author FreshR
   * @since 2024. 3. 29. 오전 10:03:07
   */
  public String generateRefreshToken(final String id) {
    return JwtUtil.generate(id);
  }

  /**
   * 토큰 조회
   *
   * @param request request
   * @return string
   * @apiNote 요청 헤더에서 토큰 정보 조회
   * @author FreshR
   * @since 2024. 3. 29. 오전 10:03:07
   */
  public String extractToken(HttpServletRequest request) {
    String header = request.getHeader(AUTHORIZATION);

    return hasLength(header) ? header.replace(BEARER_PREFIX, "") : null;
  }

  /**
   * 접근 토큰 유효성 검증
   *
   * @param token token
   * @apiNote 접근 토큰 유효성 검증
   * @author FreshR
   * @since 2024. 3. 29. 오전 10:03:07
   */
  public void validateAccessToken(final String token) {
    validateToken(token, true);
  }

  /**
   * 갱신 토큰 유효성 검증
   *
   * @param token token
   * @apiNote 갱신 토큰 유효성 검증
   * @author FreshR
   * @since 2024. 3. 29. 오전 10:03:07
   */
  public void validateRefreshToken(final String token) {
    validateToken(token, false);
  }

  /**
   * 토큰 유효성 검증
   *
   * @param token    token
   * @param isAccess is access
   * @apiNote 토큰 유효성 검증
   * @author FreshR
   * @since 2024. 3. 29. 오전 10:03:07
   */
  private void validateToken(String token, Boolean isAccess) {
    if (!hasLength(token)) {
      return;
    }

    boolean exists = isAccess ? accessRedisUnit.exists(token) : refreshRedisUnit.exists(token);

    if (!exists) { // 발급한 토큰인지 체크
      throw new UnAuthenticatedException("error validate token");
    }

    if (JwtUtil.checkExpiration(token)) { // 만료되었는지 체크
      throw new ExpiredJwtException(null, null, "error validate token");
    }
  }

  /**
   * 토큰 정보 저장
   *
   * @param accessToken access token
   * @apiNote 토큰 정보 저장
   * @author FreshR
   * @since 2024. 3. 29. 오전 10:03:07
   */
  public void setThreadLocal(String accessToken) {
    String id = "";
    Role role = ROLE_ANONYMOUS;

    if (hasLength(accessToken)) {
      AccessRedis access = accessRedisUnit.get(accessToken);

      id = access.getSignId();
      role = access.getRole();
    }

    signedId.set(id);
    signedRole.set(role);
  }

  /**
   * 인증 정보 생성
   *
   * @return authentication
   * @apiNote 인증 정보 생성
   * @author FreshR
   * @since 2024. 3. 29. 오전 10:03:07
   */
  public Authentication getAuthentication() {
    Role role = signedRole.get();

    return new UsernamePasswordAuthenticationToken(
        role.getPrivilege(),
        "{noop}",
        createAuthorityList(role.getKey())
    );
  }

  /**
   * 오류 데이터 구성
   *
   * @param exceptionData exception data
   * @return string
   * @throws JsonProcessingException json processing exception
   * @apiNote 오류 데이터 구성
   * @author FreshR
   * @since 2024. 3. 29. 오전 10:22:23
   */
  public String error(ExceptionData exceptionData) throws JsonProcessingException {
    return objectMapper.writeValueAsString(ResponseData
        .builder()
        .name(exceptionData.getHttpStatus().getReasonPhrase())
        .code(exceptionData.getCode())
        .message(exceptionData.getMessage())
        .build());
  }

}
