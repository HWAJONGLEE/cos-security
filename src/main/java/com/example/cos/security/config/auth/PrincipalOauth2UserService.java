package com.example.cos.security.config.auth;

import com.example.cos.security.model.User;
import com.example.cos.security.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    public PrincipalOauth2UserService (UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    //구글로 부터 받은 userRequest 데이터에 대한 후처리 되는 함수
    // 함수종료시 @AuthenticationPrincipal 어노테이션 생성
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthorizationException {
        log.info("userRequest  ::: {} ", userRequest.getClientRegistration()); //registrationId로 어떤 OAuth로 로그인 했는지 알 수 있음
        log.info("userRequest  ::: {} ", userRequest.getAccessToken().getTokenValue());

        log.info("userRequest  ::: {} ", userRequest.getAdditionalParameters());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        //구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인을 완료 -> Code를 리턴(OAuth-Client라이브러리) ->AccessToken 요청
        //userRequest 정보 -> loadUser 함수 호출-> 구글로부터 회원프로필을 받아줌
        log.info("userRequest  ::: {} ", oAuth2User.getAttributes());

        String provider = userRequest.getClientRegistration().getClientId(); // google (oauth를 어디서 했는지)
        String providerId = oAuth2User.getAttribute("sub");
        String username = provider + "_" + providerId; // google_1235389457483957
        String password = new BCryptPasswordEncoder().encode("겟인데어");
        String email = oAuth2User.getAttribute("email");
        String role= "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);

        if (userEntity == null) {
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }

}
