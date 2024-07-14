package com.pnegrete.ForoHub.domain.topico;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.Optional;

public interface TopicoRepository extends JpaRepository<Topico, Long> {
    Page<Topico> findByStatusTrue(Pageable paginacion);

    Optional<Topico> findByIdAndStatusTrue(Long id);

    Page<Topico> findByCurso(Curso curso, Pageable pageable);

    Page<Topico> findByCursoAndFechaCreacionBetween(Curso curso, LocalDateTime start, LocalDateTime end, Pageable pageable);

    Page<Topico> findByFechaCreacionBetween(LocalDateTime start, LocalDateTime end, Pageable pageable);
}
