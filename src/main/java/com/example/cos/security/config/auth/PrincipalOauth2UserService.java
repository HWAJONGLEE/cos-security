package com.example.cos.security.config.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    //구글로 부터 받은 userRequest 데이터에 대한 후처리 되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthorizationException {
        log.info("userRequest  ::: {} ", userRequest.getClientRegistration());
        log.info("userRequest  ::: {} ", userRequest.getAccessToken());
        log.info("userRequest  ::: {} ", userRequest.getAdditionalParameters());

        log.info("userRequest  ::: {} ", super.loadUser(userRequest).getAttributes());
        return super.loadUser(userRequest);
    }

}
