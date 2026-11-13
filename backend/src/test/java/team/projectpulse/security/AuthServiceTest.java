package team.projectpulse.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import team.projectpulse.instructor.Instructor;
import team.projectpulse.instructor.converter.InstructorToInstructorDtoConverter;
import team.projectpulse.student.converter.StudentToStudentDtoConverter;
import team.projectpulse.user.MyUserPrincipal;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    JwtProvider jwtProvider;
    @Mock
    StudentToStudentDtoConverter studentToStudentDtoConverter;
    @Mock
    InstructorToInstructorDtoConverter instructorToInstructorDtoConverter;

    @InjectMocks
    AuthService authService;

    @Test
    void createLoginInfoDoesNotCrashWhenUserHasNoRoles() {
        // An admin can save an instructor with roles = null (InstructorService.updateInstructor
        // copies update.getRoles() as-is). Such a user still authenticates, because
        // MyUserPrincipal.getAuthorities() tolerates null roles, so login reaches createLoginInfo.
        Instructor instructor = new Instructor();
        instructor.setRoles(null);
        MyUserPrincipal principal = new MyUserPrincipal(instructor);
        Authentication authentication =
                new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());

        Map<String, Object> result = this.authService.createLoginInfo(authentication);

        assertThat(result).isEmpty();
    }
}
