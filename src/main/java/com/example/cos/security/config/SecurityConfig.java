package com.example.cos.security.config;

import com.example.cos.security.config.auth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

// 1. 코드받기(인증) , 2.엑세스토큰(권한)
// 3. 사용자프로필 정보를 가져오고 4-1. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함
// 4-2 (이메일, 전화번호, 이름, 아이디) 쇼핑몰 -> (집주소), 백화점몰 -> (vip등급)


@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록됨
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) //secured 어노테이션 활성화 preAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PrincipalOauth2UserService principalOauth2UserService;


    //해당 메서드의 리턴되는 오브젝트를 IoC로 등록 해줌.
    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeHttpRequests()

                // .antMatchers("/", "/error/*", "/login", "/loginProc").permitAll() //설정된 url은 인증이 되지 않아도 접근 가능
                //.anyRequest().authenticated()// 위 페이지 외 인증이 되어야 접근가능(ROLE에 상관없이)

                .antMatchers("/user/**").authenticated() //인증만 되면 들어갈 수 있는 주소
                .antMatchers("/manager/**").hasAnyRole("ROLE_ADMIN" , "ROLE_MANAGER")
                .antMatchers("/admin/**").hasRole("ROLE_ADMIN")
                .anyRequest().permitAll() // 그 이외에는 전부 허용 인증 및 role이 없이도 허용
                .and()
                .formLogin()
                //.usernameParameter("userEmail") form에 아이디 키 값 파라미터를 시큐리티username으로 변경 해줌 ex userMail => username
                .loginPage("/loginForm") //로그인 페이지 경로
                .loginProcessingUrl("/login") // /login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행함
                .defaultSuccessUrl("/") // 로그인 후 default로 들어 가게 될 주소
                .and()
                .oauth2Login()
                .loginPage("/loginForm")
                .userInfoEndpoint()
                .userService(principalOauth2UserService); // 구글 로그인이 완료 된 후 처리 필요 완료가 되면 (코드 X) 엑세스토큰 + 사용자프로필정보를 받음

    }
}
