package com.pnegrete.ForoHub.domain.topico;

import java.time.LocalDateTime;

public record DatosListadoTopico(Long id,
                                 String autor,
                                 String mensaje,
                                 Curso curso,
                                 String titulo,
                                 LocalDateTime fechaCreacion,
                                 Boolean status) {
    public DatosListadoTopico(Topico topico) {
        this(
                topico.getId(),
                topico.getAutor(),
                topico.getMensaje(),
                topico.getCurso(),
                topico.getTitulo(),
                topico.getFechaCreacion(),
                topico.getStatus()
        );
    }
}
