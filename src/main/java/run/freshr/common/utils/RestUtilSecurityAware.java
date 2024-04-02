package run.freshr.common.utils;

import static run.freshr.common.security.TokenProvider.signedId;
import static run.freshr.common.security.TokenProvider.signedRole;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import run.freshr.common.configurations.CustomConfigurationAware;
import run.freshr.common.data.ExceptionsData;
import run.freshr.domain.account.entity.Account;
import run.freshr.domain.auth.enumerations.Role;
import run.freshr.domain.auth.unit.jpa.AccountAuthUnit;

/**
 * 자주 사용하는 공통 기능을 정의
 *
 * @param <C> type parameter
 * @author FreshR
 * @apiNote 자주 사용하는 공통 기능을 정의<br>
 *          {@link RestUtilAware} 를 상속 받아 계정 관련 기능 추가
 * @since 2024. 4. 2. 오전 11:09:37
 */
@Slf4j
@Component
@RequiredArgsConstructor
public abstract class RestUtilSecurityAware<C extends CustomConfigurationAware> extends RestUtilAware<C> {

  private static AccountAuthUnit accountAuthUnit;

  public RestUtilSecurityAware(Environment environment, ExceptionsData exceptionsData,
      AccountAuthUnit accountAuthUnit) {
    super(environment, exceptionsData);
    
    RestUtilSecurityAware.accountAuthUnit = accountAuthUnit;
  }

  /**
   * 요청한 계정 일련 번호 조회
   *
   * @return signed id
   * @apiNote 요청한 계정 일련 번호 조회
   * @author FreshR
   * @since 2024. 3. 29. 오전 11:02:33
   */
  public static String getSignedId() {
    return signedId.get();
  }

  /**
   * 요청한 계정 권한 조회
   *
   * @return signed role
   * @apiNote 요청한 계정 권한 조회
   * @author FreshR
   * @since 2024. 3. 29. 오전 11:02:33
   */
  public static Role getSignedRole() {
    return signedRole.get();
  }

  /**
   * 요청한 계정 정보를 조회
   *
   * @return signed
   * @apiNote 요청한 계정 정보를 조회
   * @author FreshR
   * @since 2024. 3. 29. 오전 11:02:33
   */
  public static Account getSigned() {
    return accountAuthUnit.get(getSignedId());
  }

}
