package com.pnegrete.ForoHub.controller;

import com.pnegrete.ForoHub.domain.usuarios.DatosAutenticacionUsuario;
import com.pnegrete.ForoHub.domain.usuarios.Usuario;
import com.pnegrete.ForoHub.infra.security.DatosJWTtoken;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.token.TokenService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/login")
public class AutenticacionController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TokenService tokenService;

    @PostMapping
    public ResponseEntity<DatosJWTtoken> autenticarUsuario(@RequestBody @Valid DatosAutenticacionUsuario datosAutenticacionUsuario) {
        try {
            Authentication authToken = new UsernamePasswordAuthenticationToken(
                    datosAutenticacionUsuario.login(),
                    datosAutenticacionUsuario.clave()
            );
            var usuarioAutenticado = authenticationManager.authenticate(authToken);
            var JWTtoken = tokenService.verifyToken(String.valueOf((Usuario) usuarioAutenticado.getPrincipal()));
            return ResponseEntity.ok(new DatosJWTtoken(JWTtoken));
        } catch (Exception e) {
            return ResponseEntity.status(401).build(); // Devuelve un 401 Unauthorized en caso de error
        }
    }
}
