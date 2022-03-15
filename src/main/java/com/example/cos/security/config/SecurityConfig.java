package com.example.cos.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록됨
public class SecurityConfig extends WebSecurityConfigurerAdapter {

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
                .defaultSuccessUrl("/"); // 로그인 후 default로 들어 가게 될 주소
    }
}
