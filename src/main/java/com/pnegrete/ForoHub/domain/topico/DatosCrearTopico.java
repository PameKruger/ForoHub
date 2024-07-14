package com.pnegrete.ForoHub.domain.topico;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record DatosCrearTopico(@NotBlank
                               String autor,
                               @NotBlank
                               String mensaje,
                               @NotNull
                               Curso curso,
                               @NotBlank
                               String titulo) {
}
